push   rbp
mov    rbp,rsp
sub    rsp,0x40
mov    DWORD PTR [rbp-0x34],edi
mov    QWORD PTR [rbp-0x40],rsi
mov    QWORD PTR [rbp-0x30],0x0
mov    QWORD PTR [rbp-0x28],0x0
mov    QWORD PTR [rbp-0x20],0x0
mov    QWORD PTR [rbp-0x18],0x0
mov    BYTE PTR [rbp-0x30],0x66
mov    BYTE PTR [rbp-0x2f],0x6c
mov    BYTE PTR [rbp-0x2e],0x61
mov    BYTE PTR [rbp-0x2d],0x67
mov    BYTE PTR [rbp-0x2c],0x7b
mov    BYTE PTR [rbp-0x2b],0x14
movzx  eax,BYTE PTR [rbp-0x2b]
mov    edx,eax
mov    eax,edx
shl    eax,0x2
add    eax,edx
mov    BYTE PTR [rbp-0x2b],al
movzx  eax,BYTE PTR [rbp-0x2b]
sub    eax,0x1
mov    BYTE PTR [rbp-0x2b],al
mov    BYTE PTR [rbp-0x2a],0x6e
movzx  eax,BYTE PTR [rbp-0x2a]
xor    eax,0x17
mov    BYTE PTR [rbp-0x2a],al
mov    BYTE PTR [rbp-0x29],0x62
movzx  eax,BYTE PTR [rbp-0x29]
sar    al,0x2
mov    BYTE PTR [rbp-0x29],al
movzx  eax,BYTE PTR [rbp-0x29]
shl    eax,0x2
mov    BYTE PTR [rbp-0x29],al
movzx  eax,BYTE PTR [rbp-0x29]
add    eax,0x2
mov    BYTE PTR [rbp-0x29],al
mov    BYTE PTR [rbp-0x28],0x30
movzx  eax,BYTE PTR [rbp-0x28]
movsx  eax,al
shl    eax,0x2
mov    BYTE PTR [rbp-0x28],al
movzx  eax,BYTE PTR [rbp-0x28]
or     eax,0xf
mov    BYTE PTR [rbp-0x28],al
movzx  eax,BYTE PTR [rbp-0x28]
add    eax,0x64
mov    BYTE PTR [rbp-0x28],al
mov    BYTE PTR [rbp-0x27],0xe
mov    DWORD PTR [rbp-0x4],0x0
jmp    0x4005f7
movzx  eax,BYTE PTR [rbp-0x27]
add    eax,0x1
mov    BYTE PTR [rbp-0x27],al
add    DWORD PTR [rbp-0x4],0x1
cmp    DWORD PTR [rbp-0x4],0x63
jle    0x4005e9
mov    BYTE PTR [rbp-0x26],0xff
movzx  eax,BYTE PTR [rbp-0x26]
lea    edx,[rax+0x3]
test   al,al
cmovs  eax,edx
sar    al,0x2
mov    BYTE PTR [rbp-0x26],al
movzx  eax,BYTE PTR [rbp-0x26]
sar    al,0x2
mov    BYTE PTR [rbp-0x26],al
movzx  eax,BYTE PTR [rbp-0x26]
add    eax,0x73
mov    BYTE PTR [rbp-0x26],al
mov    BYTE PTR [rbp-0x25],0xff
movzx  eax,BYTE PTR [rbp-0x25]
add    eax,0x4
mov    BYTE PTR [rbp-0x25],al
movzx  eax,BYTE PTR [rbp-0x25]
mov    edx,eax
mov    eax,edx
shl    eax,0x3
add    eax,edx
shl    eax,0x2
add    eax,edx
mov    BYTE PTR [rbp-0x25],al
movzx  eax,BYTE PTR [rbp-0x25]
add    eax,0xa
mov    BYTE PTR [rbp-0x25],al
movzx  eax,BYTE PTR [rbp-0x25]
sub    eax,0x9
mov    BYTE PTR [rbp-0x25],al
mov    BYTE PTR [rbp-0x24],0x3
movzx  eax,BYTE PTR [rbp-0x24]
movsx  eax,al
shl    eax,0x4
mov    BYTE PTR [rbp-0x24],al
movzx  eax,BYTE PTR [rbp-0x24]
or     eax,0x4
mov    BYTE PTR [rbp-0x24],al
mov    BYTE PTR [rbp-0x23],0x14
movzx  eax,BYTE PTR [rbp-0x23]
mov    edx,eax
mov    eax,edx
shl    eax,0x2
add    eax,edx
mov    BYTE PTR [rbp-0x23],al
movzx  eax,BYTE PTR [rbp-0x23]
sub    eax,0x1
mov    BYTE PTR [rbp-0x23],al
mov    BYTE PTR [rbp-0x22],0x30
movzx  eax,BYTE PTR [rbp-0x22]
movsx  eax,al
shl    eax,0x2
mov    BYTE PTR [rbp-0x22],al
movzx  eax,BYTE PTR [rbp-0x22]
or     eax,0xf
mov    BYTE PTR [rbp-0x22],al
movzx  eax,BYTE PTR [rbp-0x22]
add    eax,0x64
mov    BYTE PTR [rbp-0x22],al
movzx  eax,BYTE PTR [rbp-0x23]
mov    BYTE PTR [rbp-0x21],al
movzx  eax,BYTE PTR [rbp-0x21]
sub    eax,0x4
mov    BYTE PTR [rbp-0x21],al
mov    BYTE PTR [rbp-0x20],0x14
movzx  eax,BYTE PTR [rbp-0x20]
mov    edx,eax
mov    eax,edx
shl    eax,0x2
add    eax,edx
mov    BYTE PTR [rbp-0x20],al
movzx  eax,BYTE PTR [rbp-0x20]
sub    eax,0x1
mov    BYTE PTR [rbp-0x20],al
mov    BYTE PTR [rbp-0x1f],0x3
movzx  eax,BYTE PTR [rbp-0x1f]
movsx  eax,al
shl    eax,0x4
mov    BYTE PTR [rbp-0x1f],al
movzx  eax,BYTE PTR [rbp-0x1f]
or     eax,0x4
mov    BYTE PTR [rbp-0x1f],al
mov    BYTE PTR [rbp-0x1e],0x64
movzx  eax,BYTE PTR [rbp-0x1e]
add    eax,0xa
mov    BYTE PTR [rbp-0x1e],al
movzx  eax,BYTE PTR [rbp-0x1e]
sub    eax,0x1
mov    BYTE PTR [rbp-0x1e],al
mov    BYTE PTR [rbp-0x1d],0xff
movzx  eax,BYTE PTR [rbp-0x1d]
add    eax,0x4
mov    BYTE PTR [rbp-0x1d],al
movzx  eax,BYTE PTR [rbp-0x1d]
mov    edx,eax
mov    eax,edx
shl    eax,0x3
add    eax,edx
shl    eax,0x2
add    eax,edx
mov    BYTE PTR [rbp-0x1d],al
movzx  eax,BYTE PTR [rbp-0x1d]
add    eax,0xa
mov    BYTE PTR [rbp-0x1d],al
movzx  eax,BYTE PTR [rbp-0x1d]
sub    eax,0x9
mov    BYTE PTR [rbp-0x1d],al
mov    BYTE PTR [rbp-0x1c],0x7d
lea    rax,[rbp-0x30]
mov    rdi,rax