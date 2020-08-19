---
layout: post
title: "Reversing - Compfest 20 Hacker Class"
date: 2020-08-18 12:17:56 +0530
categories:
  - WriteUp
  - Hacker Class
  - Reversing
---

Berikut writeup Hacker Class Compfest 2020 pada kategori Reverse Engineering.
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

Jalankan akan memunculkan : `n!C3`

```sh
$ python solver_math.py 
n!C3

$ python soal.py 
n!C3
Congratz, here is your flag: COMPFEST12{c9ba50e8ec889ec57e3181a060f871968b3914b4e912f43d05113e901b7f555698c45871f96189cfc50062f0bd21f793}

```

### FLAG

`COMPFEST12{c9ba50e8ec889ec57e3181a060f871968b3914b4e912f43d05113e901b7f555698c45871f96189cfc50062f0bd21f793}`\
<br />


## 2. Half Life 3 [103 pts]

Diberikan file python, berikut isi filenya.

```py
(lambda x: print('Congratz, here is your flag: COMPFEST12{' + x + '}') if (lambda a: int((lambda b: ''.join([chr((ord(i)-97+1+(1^2))%26+97) for i in b]))(a), 36) if all([i in __import__('string').ascii_lowercase[-1:]+__import__('string').ascii_lowercase[:-1] for i in a]) else -1)(x) == 16166842727364078278681384436557013 else print('Nope'))(input().lower())
```

Dimana inputan akan dishift (caesar cipher), lalu dikorversi kedalam bilangan berbasis 36. Lalu akan dibandingkan apakah hasilnya `16166842727364078278681384436557013`. Untuk itu, tinggal decode hasil yang diinginkan kedalam bentuk ascii, lalu dishift kekiri 24 kali dan didapatkan input yang dicari.

<!-- ```py
int( (lambda b: ''.join([chr((ord(i)-97+1+(1^2))%26+97) for i in b])) (a), 36)
``` -->
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

Jalankan dan didapatkan flag.

```sh
$ python solver.py 
thatwasntthathardright

$ python3 soal.py 
thatwasntthathardright
Congratz, here is your flag: COMPFEST12{thatwasntthathardright}

```

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

```sh
$ python solver.py 
...
COMPFEST12{tH3_c4T_15_v3rY_Caee}
COMPFEST12{tH3_c4T_15_v3rY_Cuet}
COMPFEST12{tH3_c4T_15_v3rY_Cute}
COMPFEST12{tH3_c4T_15_v3rY_Cutt}
...
```

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

```sh
$ python solver.py 
COMPFEST12{w0W_u_c4n_r3Ad_w3lL}
```

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

Didapatkan flag tetapi dengan tertukar-tukar antara index ganjil dengan index setelahnya.

```sh
$ python solver.py 
OCMPEFTS21b{nerak_na_no_niject_ijnec_toll}
```

Dengan memindahkan index-index yang tertukar secara manual, dan didapatkan flag yang benar.

### FLAG

`COMPFEST12{benar_kan_no_inject_inject_lol}`\
<br/>
<br/>

Nice Chall !