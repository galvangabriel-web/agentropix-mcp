# Raw verification capture — network-capture evidence

Generated: 2026-06-13T01:01:26Z on the SIFT workstation.
Commands shown verbatim; every file verified by magic bytes (`file`), first-16-bytes hex (`xxd`), and SHA-256.

## Acquired captures

```
$ file "/cases/nist5/DFRWS2005-RODEO/rhino.log"
/cases/nist5/DFRWS2005-RODEO/rhino.log: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65000)
$ xxd -l 16 "/cases/nist5/DFRWS2005-RODEO/rhino.log"
00000000: d4c3 b2a1 0200 0400 0000 0000 0000 0000  ................
$ sha256sum + size
64e6d55b76660eb3aaa41572c1d04e4452510a343bbf42e844424827dedfddb2  /cases/nist5/DFRWS2005-RODEO/rhino.log
3187907 bytes
---
$ file "/cases/nist5/DFRWS2005-RODEO/rhino2.log"
/cases/nist5/DFRWS2005-RODEO/rhino2.log: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65000)
$ xxd -l 16 "/cases/nist5/DFRWS2005-RODEO/rhino2.log"
00000000: d4c3 b2a1 0200 0400 0000 0000 0000 0000  ................
$ sha256sum + size
41939d5de0556b70279056572dee44b6fd84cd05b0788cfd0b6f52f37b161dde  /cases/nist5/DFRWS2005-RODEO/rhino2.log
292604 bytes
---
$ file "/cases/nist5/DFRWS2005-RODEO/rhino3.log"
/cases/nist5/DFRWS2005-RODEO/rhino3.log: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65000)
$ xxd -l 16 "/cases/nist5/DFRWS2005-RODEO/rhino3.log"
00000000: d4c3 b2a1 0200 0400 0000 0000 0000 0000  ................
$ sha256sum + size
7b0304f5e88a30c305a99b5a1e2977bced5b9c94da6f458f887bb39966bbfc46  /cases/nist5/DFRWS2005-RODEO/rhino3.log
226094 bytes
---
$ file "/tmp/agentropix-sift-vanko/collect/documents-media/Documents/testpcap.pcap"
/tmp/agentropix-sift-vanko/collect/documents-media/Documents/testpcap.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (802.11 with radiotap header, capture length 65535)
$ xxd -l 16 "/tmp/agentropix-sift-vanko/collect/documents-media/Documents/testpcap.pcap"
00000000: d4c3 b2a1 0200 0400 0000 0000 0000 0000  ................
$ sha256sum + size
6f27e008d0d6afee2f945f46e9597ce418512fa4ee7c283a060412d44a08a559  /tmp/agentropix-sift-vanko/collect/documents-media/Documents/testpcap.pcap
147899 bytes
---
$ file "/tmp/agentropix-sift-vanko/collect/documents-media/Documents/starbucks pcap.pcap"
/tmp/agentropix-sift-vanko/collect/documents-media/Documents/starbucks pcap.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (802.11 with radiotap header, capture length 65535)
$ xxd -l 16 "/tmp/agentropix-sift-vanko/collect/documents-media/Documents/starbucks pcap.pcap"
00000000: d4c3 b2a1 0200 0400 0000 0000 0000 0000  ................
$ sha256sum + size
ff62aa8a277ec945827343379a02785a1bd0fd09b7e7aecebf398d931399abc1  /tmp/agentropix-sift-vanko/collect/documents-media/Documents/starbucks pcap.pcap
195688 bytes
---
```

## Carved captures (bulk_extractor derivatives)

```
$ file /tmp/agentropix-sift-srl2015-ctrl-be/packets.pcap
/tmp/agentropix-sift-srl2015-ctrl-be/packets.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
$ sha256sum + size
5bbc90e066b6545da66dde9d4405a3604767952595c365797f3eea9f6139223f  /tmp/agentropix-sift-srl2015-ctrl-be/packets.pcap
34072 bytes
---
$ file /tmp/agentropix-sift-srl2018-be/packets.pcap
/tmp/agentropix-sift-srl2018-be/packets.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
$ sha256sum + size
dbfa796d5bd562aadd9d7892a67ba071393618a14ead5705a7dc4b309dfc0755  /tmp/agentropix-sift-srl2018-be/packets.pcap
63624 bytes
---
$ file /tmp/agentropix-sift-nist1/packets.pcap
/tmp/agentropix-sift-nist1/packets.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
$ sha256sum + size
4cdf9abed715887dc3ee59bc27d37237c92a6c0884f31871288dd6398d29ec29  /tmp/agentropix-sift-nist1/packets.pcap
301634 bytes
---
$ file /tmp/agentropix-sift-nist1-run3/packets.pcap
/tmp/agentropix-sift-nist1-run3/packets.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
$ sha256sum + size
79654560f1106713e98b56af3f1a7a33970ee0517fcf3d9e6cd8b45c035e6c30  /tmp/agentropix-sift-nist1-run3/packets.pcap
301634 bytes
---
$ file /tmp/agentropix-sift-validate-be/packets.pcap
/tmp/agentropix-sift-validate-be/packets.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
$ sha256sum + size
fa665761ddcadd68116952a4ba1d1f1b2e1a82ae487889c3faa06e294106b336  /tmp/agentropix-sift-validate-be/packets.pcap
301634 bytes
---
$ file /tmp/agentropix-sift-bulk-87exw9p0/packets.pcap
/tmp/agentropix-sift-bulk-87exw9p0/packets.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
$ sha256sum + size
8e3d598234a8a1baea3d628dd8fb4174e2aa0bfb2ffebc79ca347c86ca2376c1  /tmp/agentropix-sift-bulk-87exw9p0/packets.pcap
965681 bytes
---
```
