# SRL-2015-APT-ENTERPRISE — Disassembly & Injection Mechanism

Bitness: 32-bit x86 (stdcall: ret 0xC/0x10/0x18 immediate-pop epilogues; 32-bit operands).
Capture: 8192-byte volatility `malfind` page dumps (5 samples, 2 code variants).

## Header (first 8 bytes)
`08 00 00 00 00 00 00 00` = an 8-byte little-endian length/offset prefix = 0x08, the file
offset at which the entry stub (the E9 JMP) begins. Code does NOT start at offset 0; it starts
at offset 8.

## Entry stub
- Variant A (17,18): off 8 `E9 F7 07 00 00` = jmp 0x804.
- Variant B (19,20,21): off 8 `E9 60 08 00 00` = jmp 0x86D.
- JMP target = the real entry routine. Function at offset 0x0D (right after the JMP,
  prologue 55 8B EC / 83 EC 30) = a decompression worker.

## API resolution
By NAME via GetModuleHandleA/LoadLibraryA + GetProcAddress (plaintext strings, NOT API hashing).
PIC import resolver at file off 0x10D8: `call $+5; pop ebx; sub ebx,<delta>` self-locate, then
loops the import-name list (kernel32/user32 + OpenProcess, VirtualProtect, GetModuleHandleA,
ExitProcess, CloseHandle, MessageBoxA, wsprintfA), supports ordinal imports
(test eax,0x80000000 = IMAGE_ORDINAL_FLAG), writes resolved addrs into an IAT. Error format
strings present: "The procedure %s could not be located in the DLL %s." / "The ordinal %d ...".
msvbvm60 (VB6 runtime) referenced — VB6-packed loader stub.

## Injection / exec primitive
The entry routine receives a struct of pre-resolved API pointers from its caller:
  [ptr+0x08] = VirtualAlloc, [ptr+0x0C] = VirtualFree.
Flow: VirtualAlloc(NULL, computed_size, MEM_COMMIT|? , PAGE_READWRITE)  (push 0x1000, push 0x4)
  -> call worker @0xD to decompress embedded blob into the buffer
  -> VirtualFree(buf, 0, MEM_RELEASE)  (push 0x8000, push 0).
Size calc: byte[hdr+4] idiv 9, idiv 5 -> (0x300<<cl)+0x736)<<4. The reusable RWX/exec stage is
set up by the surrounding loader (VirtualProtect from the import list); OpenProcess in the import
list = cross-process injection capability of the parent loader.

## Second stage
The worker at 0xD is an LZMA-family RANGE DECODER (signatures: range>>11 (shr esi,0xB),
kTopValue 0x800, probability update shr 5, range-renorm threshold 0x1000000, prob tables indexed
by imul esi,esi,0xC00 / +0x1CD8). i.e. the second stage is an LZMA-COMPRESSED embedded payload
that the stub decompresses in memory. No plaintext MZ/PE in the dumped page (payload is compressed;
data region after the decoder, off ~0x890+ and ~0x10CB+, is what differs per host capture).
