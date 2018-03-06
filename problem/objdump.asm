0000000000400526 <main>:
400526: 55                    push   rbp
400527: 48 89 e5              mov    rbp,rsp
40052a: 48 83 ec 40           sub    rsp,0x40
40052e: 89 7d cc              mov    DWORD PTR [rbp-0x34],edi
400531: 48 89 75 c0           mov    QWORD PTR [rbp-0x40],rsi
400535: 48 c7 45 d0 00 00 00  mov    QWORD PTR [rbp-0x30],0x0
40053c: 00 
40053d: 48 c7 45 d8 00 00 00  mov    QWORD PTR [rbp-0x28],0x0
400544: 00 
400545: 48 c7 45 e0 00 00 00  mov    QWORD PTR [rbp-0x20],0x0
40054c: 00 
40054d: 48 c7 45 e8 00 00 00  mov    QWORD PTR [rbp-0x18],0x0
400554: 00 
400555: c6 45 d0 66           mov    BYTE PTR [rbp-0x30],0x66
400559: c6 45 d1 6c           mov    BYTE PTR [rbp-0x2f],0x6c
40055d: c6 45 d2 61           mov    BYTE PTR [rbp-0x2e],0x61
400561: c6 45 d3 67           mov    BYTE PTR [rbp-0x2d],0x67
400565: c6 45 d4 7b           mov    BYTE PTR [rbp-0x2c],0x7b
400569: c6 45 d5 14           mov    BYTE PTR [rbp-0x2b],0x14
40056d: 0f b6 45 d5           movzx  eax,BYTE PTR [rbp-0x2b]
400571: 89 c2                 mov    edx,eax
400573: 89 d0                 mov    eax,edx
400575: c1 e0 02              shl    eax,0x2
400578: 01 d0                 add    eax,edx
40057a: 88 45 d5              mov    BYTE PTR [rbp-0x2b],al
40057d: 0f b6 45 d5           movzx  eax,BYTE PTR [rbp-0x2b]
400581: 83 e8 01              sub    eax,0x1
400584: 88 45 d5              mov    BYTE PTR [rbp-0x2b],al
400587: c6 45 d6 6e           mov    BYTE PTR [rbp-0x2a],0x6e
40058b: 0f b6 45 d6           movzx  eax,BYTE PTR [rbp-0x2a]
40058f: 83 f0 17              xor    eax,0x17
400592: 88 45 d6              mov    BYTE PTR [rbp-0x2a],al
400595: c6 45 d7 62           mov    BYTE PTR [rbp-0x29],0x62
400599: 0f b6 45 d7           movzx  eax,BYTE PTR [rbp-0x29]
40059d: c0 f8 02              sar    al,0x2
4005a0: 88 45 d7              mov    BYTE PTR [rbp-0x29],al
4005a3: 0f b6 45 d7           movzx  eax,BYTE PTR [rbp-0x29]
4005a7: c1 e0 02              shl    eax,0x2
4005aa: 88 45 d7              mov    BYTE PTR [rbp-0x29],al
4005ad: 0f b6 45 d7           movzx  eax,BYTE PTR [rbp-0x29]
4005b1: 83 c0 02              add    eax,0x2
4005b4: 88 45 d7              mov    BYTE PTR [rbp-0x29],al
4005b7: c6 45 d8 30           mov    BYTE PTR [rbp-0x28],0x30
4005bb: 0f b6 45 d8           movzx  eax,BYTE PTR [rbp-0x28]
4005bf: 0f be c0              movsx  eax,al
4005c2: c1 e0 02              shl    eax,0x2
4005c5: 88 45 d8              mov    BYTE PTR [rbp-0x28],al
4005c8: 0f b6 45 d8           movzx  eax,BYTE PTR [rbp-0x28]
4005cc: 83 c8 0f              or     eax,0xf
4005cf: 88 45 d8              mov    BYTE PTR [rbp-0x28],al
4005d2: 0f b6 45 d8           movzx  eax,BYTE PTR [rbp-0x28]
4005d6: 83 c0 64              add    eax,0x64
4005d9: 88 45 d8              mov    BYTE PTR [rbp-0x28],al
4005dc: c6 45 d9 0e           mov    BYTE PTR [rbp-0x27],0xe
4005e0: c7 45 fc 00 00 00 00  mov    DWORD PTR [rbp-0x4],0x0
4005e7: eb 0e                 jmp    4005f7 <main+0xd1>
4005e9: 0f b6 45 d9           movzx  eax,BYTE PTR [rbp-0x27]
4005ed: 83 c0 01              add    eax,0x1
4005f0: 88 45 d9              mov    BYTE PTR [rbp-0x27],al
4005f3: 83 45 fc 01           add    DWORD PTR [rbp-0x4],0x1
4005f7: 83 7d fc 63           cmp    DWORD PTR [rbp-0x4],0x63
4005fb: 7e ec                 jle    4005e9 <main+0xc3>
4005fd: c6 45 da ff           mov    BYTE PTR [rbp-0x26],0xff
400601: 0f b6 45 da           movzx  eax,BYTE PTR [rbp-0x26]
400605: 8d 50 03              lea    edx,[rax+0x3]
400608: 84 c0                 test   al,al
40060a: 0f 48 c2              cmovs  eax,edx
40060d: c0 f8 02              sar    al,0x2
400610: 88 45 da              mov    BYTE PTR [rbp-0x26],al
400613: 0f b6 45 da           movzx  eax,BYTE PTR [rbp-0x26]
400617: c0 f8 02              sar    al,0x2
40061a: 88 45 da              mov    BYTE PTR [rbp-0x26],al
40061d: 0f b6 45 da           movzx  eax,BYTE PTR [rbp-0x26]
400621: 83 c0 73              add    eax,0x73
400624: 88 45 da              mov    BYTE PTR [rbp-0x26],al
400627: c6 45 db ff           mov    BYTE PTR [rbp-0x25],0xff
40062b: 0f b6 45 db           movzx  eax,BYTE PTR [rbp-0x25]
40062f: 83 c0 04              add    eax,0x4
400632: 88 45 db              mov    BYTE PTR [rbp-0x25],al
400635: 0f b6 45 db           movzx  eax,BYTE PTR [rbp-0x25]
400639: 89 c2                 mov    edx,eax
40063b: 89 d0                 mov    eax,edx
40063d: c1 e0 03              shl    eax,0x3
400640: 01 d0                 add    eax,edx
400642: c1 e0 02              shl    eax,0x2
400645: 01 d0                 add    eax,edx
400647: 88 45 db              mov    BYTE PTR [rbp-0x25],al
40064a: 0f b6 45 db           movzx  eax,BYTE PTR [rbp-0x25]
40064e: 83 c0 0a              add    eax,0xa
400651: 88 45 db              mov    BYTE PTR [rbp-0x25],al
400654: 0f b6 45 db           movzx  eax,BYTE PTR [rbp-0x25]
400658: 83 e8 09              sub    eax,0x9
40065b: 88 45 db              mov    BYTE PTR [rbp-0x25],al
40065e: c6 45 dc 03           mov    BYTE PTR [rbp-0x24],0x3
400662: 0f b6 45 dc           movzx  eax,BYTE PTR [rbp-0x24]
400666: 0f be c0              movsx  eax,al
400669: c1 e0 04              shl    eax,0x4
40066c: 88 45 dc              mov    BYTE PTR [rbp-0x24],al
40066f: 0f b6 45 dc           movzx  eax,BYTE PTR [rbp-0x24]
400673: 83 c8 04              or     eax,0x4
400676: 88 45 dc              mov    BYTE PTR [rbp-0x24],al
400679: c6 45 dd 14           mov    BYTE PTR [rbp-0x23],0x14
40067d: 0f b6 45 dd           movzx  eax,BYTE PTR [rbp-0x23]
400681: 89 c2                 mov    edx,eax
400683: 89 d0                 mov    eax,edx
400685: c1 e0 02              shl    eax,0x2
400688: 01 d0                 add    eax,edx
40068a: 88 45 dd              mov    BYTE PTR [rbp-0x23],al
40068d: 0f b6 45 dd           movzx  eax,BYTE PTR [rbp-0x23]
400691: 83 e8 01              sub    eax,0x1
400694: 88 45 dd              mov    BYTE PTR [rbp-0x23],al
400697: c6 45 de 30           mov    BYTE PTR [rbp-0x22],0x30
40069b: 0f b6 45 de           movzx  eax,BYTE PTR [rbp-0x22]
40069f: 0f be c0              movsx  eax,al
4006a2: c1 e0 02              shl    eax,0x2
4006a5: 88 45 de              mov    BYTE PTR [rbp-0x22],al
4006a8: 0f b6 45 de           movzx  eax,BYTE PTR [rbp-0x22]
4006ac: 83 c8 0f              or     eax,0xf
4006af: 88 45 de              mov    BYTE PTR [rbp-0x22],al
4006b2: 0f b6 45 de           movzx  eax,BYTE PTR [rbp-0x22]
4006b6: 83 c0 64              add    eax,0x64
4006b9: 88 45 de              mov    BYTE PTR [rbp-0x22],al
4006bc: 0f b6 45 dd           movzx  eax,BYTE PTR [rbp-0x23]
4006c0: 88 45 df              mov    BYTE PTR [rbp-0x21],al
4006c3: 0f b6 45 df           movzx  eax,BYTE PTR [rbp-0x21]
4006c7: 83 e8 04              sub    eax,0x4
4006ca: 88 45 df              mov    BYTE PTR [rbp-0x21],al
4006cd: c6 45 e0 14           mov    BYTE PTR [rbp-0x20],0x14
4006d1: 0f b6 45 e0           movzx  eax,BYTE PTR [rbp-0x20]
4006d5: 89 c2                 mov    edx,eax
4006d7: 89 d0                 mov    eax,edx
4006d9: c1 e0 02              shl    eax,0x2
4006dc: 01 d0                 add    eax,edx
4006de: 88 45 e0              mov    BYTE PTR [rbp-0x20],al
4006e1: 0f b6 45 e0           movzx  eax,BYTE PTR [rbp-0x20]
4006e5: 83 e8 01              sub    eax,0x1
4006e8: 88 45 e0              mov    BYTE PTR [rbp-0x20],al
4006eb: c6 45 e1 03           mov    BYTE PTR [rbp-0x1f],0x3
4006ef: 0f b6 45 e1           movzx  eax,BYTE PTR [rbp-0x1f]
4006f3: 0f be c0              movsx  eax,al
4006f6: c1 e0 04              shl    eax,0x4
4006f9: 88 45 e1              mov    BYTE PTR [rbp-0x1f],al
4006fc: 0f b6 45 e1           movzx  eax,BYTE PTR [rbp-0x1f]
400700: 83 c8 04              or     eax,0x4
400703: 88 45 e1              mov    BYTE PTR [rbp-0x1f],al
400706: c6 45 e2 64           mov    BYTE PTR [rbp-0x1e],0x64
40070a: 0f b6 45 e2           movzx  eax,BYTE PTR [rbp-0x1e]
40070e: 83 c0 0a              add    eax,0xa
400711: 88 45 e2              mov    BYTE PTR [rbp-0x1e],al
400714: 0f b6 45 e2           movzx  eax,BYTE PTR [rbp-0x1e]
400718: 83 e8 01              sub    eax,0x1
40071b: 88 45 e2              mov    BYTE PTR [rbp-0x1e],al
40071e: c6 45 e3 ff           mov    BYTE PTR [rbp-0x1d],0xff
400722: 0f b6 45 e3           movzx  eax,BYTE PTR [rbp-0x1d]
400726: 83 c0 04              add    eax,0x4
400729: 88 45 e3              mov    BYTE PTR [rbp-0x1d],al
40072c: 0f b6 45 e3           movzx  eax,BYTE PTR [rbp-0x1d]
400730: 89 c2                 mov    edx,eax
400732: 89 d0                 mov    eax,edx
400734: c1 e0 03              shl    eax,0x3
400737: 01 d0                 add    eax,edx
400739: c1 e0 02              shl    eax,0x2
40073c: 01 d0                 add    eax,edx
40073e: 88 45 e3              mov    BYTE PTR [rbp-0x1d],al
400741: 0f b6 45 e3           movzx  eax,BYTE PTR [rbp-0x1d]
400745: 83 c0 0a              add    eax,0xa
400748: 88 45 e3              mov    BYTE PTR [rbp-0x1d],al
40074b: 0f b6 45 e3           movzx  eax,BYTE PTR [rbp-0x1d]
40074f: 83 e8 09              sub    eax,0x9
400752: 88 45 e3              mov    BYTE PTR [rbp-0x1d],al
400755: c6 45 e4 7d           mov    BYTE PTR [rbp-0x1c],0x7d
400759: 48 8d 45 d0           lea    rax,[rbp-0x30]
40075d: 48 89 c7              mov    rdi,rax
400760: e8 9b fc ff ff        call   400400 <puts@plt>
400765: b8 00 00 00 00        mov    eax,0x0
40076a: c9                    leave  
40076b: c3                    ret    
40076c: 0f 1f 40 00           nop    DWORD PTR [rax+0x0]