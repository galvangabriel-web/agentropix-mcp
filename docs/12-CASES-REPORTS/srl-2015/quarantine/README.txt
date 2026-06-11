==============================================================================
  !!!  WARNING - LIVE MALWARE QUARANTINE  !!!
  Case: SRL-2015-APT-ENTERPRISE
==============================================================================

This directory contains LIVE, ACTIVE MALWARE samples carved from the case
evidence disk images. DO NOT extract, open, double-click, or execute any
sample on a production host, an internet-connected host, or any system you
are not prepared to destroy/reimage.

CONTENTS
--------
  srl2015-samples.zip   - password-protected archive of ALL carved samples.
                          ARCHIVE PASSWORD:  infected
                          (industry-standard malware-sharing password)
  MANIFEST.csv          - one row per carved sample: in-zip name, original
                          on-disk path, source host, expected IOC hash,
                          carved SHA-256, verified flag (Y/N), size.

HANDLING
--------
  * Open ONLY inside an isolated, disposable malware-analysis VM with NO
    network (or a controlled detonation sandbox).
  * The .exe extension is retained for analyst clarity. The files inside the
    zip are NOT marked executable; they were copied with `cp`, never run.
  * To extract for analysis:   unzip -P infected srl2015-samples.zip
  * The zip is mode 0600.

WHAT WAS CARVED
---------------
  16 file copies were carved, spanning 4 distinct malicious file hashes.
  Every carved SHA-256 was re-computed AFTER copy and matched the expected
  IOC hash from exports/iocs.json (all verified = Y, 0 mismatches):

    5420d06d... usboesrv.exe  (USB-over-Ethernet trojan)  - controller (x2)
    598e53b6... a.exe         (dropper, in user/Windows Temp) - nfury, nromanoff, xp (x6)
    6eef2381... spinlock.exe  (System32 implant)          - nfury, nromanoff, xp (x3)
    f293fdb9... svchost.exe   (masquerading svchost in dllhost\ + Recycle.Bin) - nfury, nromanoff, xp (x3)

  Source: read-only ewfmount of the per-host *-c-drive.E01 images under
  /cases/SRL-2015/, NTFS mounted read-only (ro,loop). No evidence was
  modified; carving was copy-only.

TARGETS NOT CARVED (documented, not failures)
---------------------------------------------
  Six malicious file-hash IOCs from exports/iocs.json have NO corresponding
  executable FILE on any host disk image, so nothing could be carved for them:

    dd8ac01d...  (femc.exe) - this hash is an 8192-byte memory-injection
                 payload (malfind, T1055) recorded against the f-response
                 femc.exe PROCESS in the controller RAM dump, NOT an on-disk
                 file. The femc.exe binary that DOES exist on disk
                 (\Program Files\F-Response\femc.exe) is the legitimate
                 F-Response forensic agent and does not match this hash.
                 (femc.exe is the single EAR "suspect=true" entry in ear.json.)
    42f33a83..., 73cb9ad7..., e855864a..., a8f9a210...
                 - likewise 8192-byte malfind memory-injection payloads
                 (T1055) from the controller / nfury RAM dumps; in-RAM
                 injected code, never persisted as a disk file.
    5420d06d... is on disk (carved). The remaining TI-only hashes
                 (598e53b6, 6eef2381, f293fdb9) were also located on disk
                 and carved above.

  These memory-resident payloads cannot be carved from the E01 disk images;
  they would have to be re-extracted from the *-memory-raw.001 RAM dumps with
  the memory-analysis tooling (volatility malfind), which is outside the
  scope of this disk-carve task. They are intentionally recorded as
  "not_found" on disk rather than fabricated.

==============================================================================
