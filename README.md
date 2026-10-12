# PitchScope_Player-Load_Next_Data_Forward-OOB
CWE-122: Heap-based Buffer Overflow / CWE-787: Out-of-bounds Write（OOB READ，CWE-125）
## Vulnerability Overview
PitchScope Player is an archived audio player maintained by Creative Detectors.
An out-of-bounds read vulnerability exists in `AudioStaticPlayer::Load_Next_Data_Forward_OOB`.
The code reads beyond the bounds of an allocated heap buffer when processing audio sample data.
This is a single-thread heap out-of-bounds read vulnerability.

Affected commit:
`8fa46c8f3c6b1407925942f94e888fb5d2c1bbae`

Affected source file in original repository:
`Src/comnAudio/AudioPlayer.cpp`

## ASAN Crash Log
=================================================================
==8214==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000040 at pc 0x5b5da5ea3af4 bp 0x7ffc0942e990 sp 0x7ffc0942e988
READ of size 1 at 0x602000000040 thread T0
#0 0x5b5da5ea3af3 in AudioStaticPlayer::Load_Next_Data_Forward_OOB(long, long) /home/lloyd/Documents/PitchScope_Player-master/vul3_harness.cpp:48:24
#1 0x5b5da5ea3668 in main /home/lloyd/Documents/PitchScope_Player-master/vul3_harness.cpp:65:12
#2 0x7db466229d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
#3 0x7db466229e3f in __libc_start_main csu/../csu/libc-start.c:392:3
#4 0x5b5da5de3314 in _start (/home/lloyd/Documents/PitchScope_Player-master/poc_vul3+0x1e314) (BuildId: 16561ad39f908165077b0d6e4912d653c2d8b08c)
0x602000000040 is located 0 bytes to the right of 16-byte region [0x602000000030,0x602000000040)
allocated by thread T0 here:
#0 0x5b5da5e6615e in malloc (/home/lloyd/Documents/PitchScope_Player-master/poc_vul3+0xa115e) (BuildId: 16561ad39f908165077b0d6e4912d653c2d8b08c)
#1 0x5b5da5ea3882 in BitSourceStatic::Alloc_Static_Block(long) /home/lloyd/Documents/PitchScope_Player-master/vul3_harness.cpp:19:31
#2 0x5b5da5ea3629 in main /home/lloyd/Documents/PitchScope_Player-master/vul3_harness.cpp:61:13
#3 0x7db466229d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
SUMMARY: AddressSanitizer: heap-buffer-overflow /home/lloyd/Documents/PitchScope_Player-master/vul3_harness.cpp:48:24 in AudioStaticPlayer::Load_Next_Data_Forward_OOB(long, long)
==8214==ABORTING


## Reproduction
1. Compile with Clang + AddressSanitizer
```bash
clang++ -fsanitize=address vul3_harness.cpp -o poc_vul3

./poc_vul3

Impact
Denial of service
Memory information disclosure
Limited potential for code execution (this is an OOB read, not OOB write)
CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L
Discoverer
Lidi Jie, School of Cyber Science and Engineering, Wuhan University

* Vulnerability type info：Other or Unknown
* Other vulnerability type info：Out-of-bounds Read

* Vendor of the product(s) info：Creative Detectors
* Product：PitchScope Player
* Version：8fa46c8f3c6b1407925942f94e888fb5d2c1bbae (no tagged releases, archived project)

Optional
Has vendor confirmed or acknowledged the vulnerability? No
Attack type info：Local
Impact info：Information Disclosure, Denial of Service（Code Execution 不勾选！I:N）

Affected component(s)
`Src/comnAudio/AudioPlayer.cpp, AudioStaticPlayer::Load_Next_Data_Forward_OOB(), static audio block reading`

Attack vector(s)
To exploit this vulnerability, an attacker must locally execute the vulnerable PitchScope Player binary and trigger out-of-bounds memory read when reading static audio block data.
plaintext

Suggested description
An out-of-bounds read vulnerability (CWE-125) exists in PitchScope Player in AudioStaticPlayer::Load_Next_Data_Forward_OOB. The program reads past the end of a heap-allocated static audio buffer. Successful exploitation may result in denial of service and memory information disclosure. Arbitrary code execution is not expected for this out-of-bounds read.
plaintext

Discoverer(s)/Credits info
`Lidi Jie, School of Cyber Science and Engineering, Wuhan University`

Reference(s) info
https://github.com/programmervuln/PitchScope_Player-Load_Next_Data_Forward-OOB/tree/main
https://github.com/CreativeDetectors/PitchScope_Player/blob/8fa46c8/Src/comnAudio/AudioPlayer.cpp
plaintext

Additional information
CWE-125 (Out-of-bounds Read) heap buffer overflow read vulnerability in PitchScope Player.
The function AudioStaticPlayer::Load_Next_Data_Forward_OOB reads beyond the boundary of heap allocated static audio block.
This is a single-thread out-of-bounds read vulnerability, not use-after-free or race condition.
CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L
Affected commit: 8fa46c8
Vulnerable source file: Src/comnAudio/AudioPlayer.cpp
The crash can be reproduced and captured by AddressSanitizer, showing heap-buffer-overflow read inside AudioStaticPlayer::Load_Next_Data_Forward_OOB().
Successful exploitation may cause denial of service and memory information disclosure. This vulnerability is an out-of-bounds read; arbitrary code execution is not anticipated.
