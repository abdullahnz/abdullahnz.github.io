---
layout: post
title: "Cryptography - Compfest 20 Hacker Class"
date: 2020-08-18 12:17:56 +0530
categories:
  - WriteUp
  - Hacker Class
  - Crypto
---

Berikut writeup Hacker Class Compfest 2020 pada kategori Cryptography.\
Dibuat juga karena gabut :)

<br />  

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

```sh
$ python solver.py 
31 COMPFEST12{eA5y_XoR3d_cRYp7}
```

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

```sh
$ python solver.py 
COMPFEST12{rsa_isnt_that_hard_as_long_as_you_know_how_it_works!}
```

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

```sh
$ python3 solver.py
COMPFEST12{budayakan_jujur_dan_tamvan_007_12aba}
```

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

```sh
$ python solver.py 
[+] Opening connection to 128.199.104.41 on port 25300: Done
[*] "el_psy_congroo 
[*] high_entropy_pseudo_random_bytes                
[*] COMPFEST12{private_member_is_an_illusion}       
[*] you_dont_need_cryptography_here 
[*] mikuru_asahina_learns_ctf_with_yuki"            
[*] "el_psy_congroo 
[*] high_entropy_pseudo_random_bytes                
[*] COMPFEST12{private_member_is_an_illusion}       
[*] you_dont_need_cryptography_here 
[*] Closed connection to 128.199.104.41 port 25300

```

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

```sh
$ python solver.py 
COMPFEST12{OFB_sucks_dont_use_it_no_more}

```

### FLAG

`COMPFEST12{OFB_sucks_dont_use_it_no_more}`\
<br/>

