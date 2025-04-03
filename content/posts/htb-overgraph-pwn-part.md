+++
title = "HTB: Overgraph - Binary Exploitation Part"
date = "2022-07-19 15:57:28 +0700"
tags = ["dark"]
+++

## 0x01 Overview

Beberapa minggu yang lalu, aku diminta untuk mengerjakan soal pwn pentest dari machine yang terdapat pada [HackTheBox](http://www.hackthebox.com/) oleh temanku. Karena ada waktu buat bantu ngerjain maka aku coba soalnya. Dan karena machine-nya memiliki kategori `hard` jadi disuruh juga buat writeupnya.

Binary merupakan ELF 64-bit dan running di mesin `ubuntu` dengan libc version `2.25` yang digunakan untuk membuat report suatu pesan. Report ini akan menulis pesan ke `/opt/crv/<name>`.

Berikut contoh tampilan program,

    $ ./nreport
    Custom Reporting v1

    Enter Your Token: <SOME_VALID_TOKEN>
    Enter Name: <NAME>

    Welcome <NAME>
    1.Create New Message
    2.Delete a Message
    3.Edit Messages
    4.Report All Messages
    5.Exit
    >

## 0x02 Reversing the Binary

Binary tidak memiliki fungsi-fungsi yang rumit, sehingga dapat dengan mudah untuk di-reversing.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
    ...
    puts("Custom Reporting v1\n");
    auth(&token);
    printf("\nWelcome %s", userinfo1, argv);
    do
    {
        puts("\n1.Create New Message\n2.Delete a Message\n3.Edit Messages\n4.Report All Messages\n5.Exit");
        printf("> ");
        scanf(" %1[^\n]", buf);
        choice = atoi(buf);
    }
    while ( choice > 5 );
    ...
}
```

### Token Authentication

Pengecekan token input dari user terdapat pada fungsi `auth` yang terdapat pada binary. Berikut hasil dekompilasi fungsi `auth` yang sudah dirapikan.

```c
...
printf("Enter Your Token: ");
fgets(&token, 19, stdin)

if ( strlen(&token) != 15 )
    goto INVALID_TOKEN;

for (int i = 13; i >= 0; --i )
    hash[i] = token[13] ^ token[9] ^ token[0] ^ token[2] ^ token[1] ^ secret[i];

if (hash[0] + hash[1] + hash[2] != 308)
    goto INVALID_TOKEN;

if (hash[7] + hash[8] + hash[9] != 325)
    goto INVALID_TOKEN;

if (hash[11] + hash[12] + hash[13] != 265)
    goto INVALID_TOKEN;
...
printf("Enter Name: ", 19);
scanf(" %39[^\n]", userinfo1);
...
```

Seharusnya alur pengecekan token sudah lebih jelas untuk mendapatkan token yang valid,

- Token harus memiliki panjang 15 karakter.
- Nilai `hash` merupakan hasil xor antara beberapa byte dari token dan `secret[i]` dengan nilai `i` yang selaras dengan index dari `hash`.
- Nilai dari beberapa `hash` merupakan nilai yang digunakan untuk pengecekan token yang valid.
- Jika pengecekan token lolos, maka akan ada inputan name yang akan disimpan pada `userinfo1`, dan jika gagal maka program akan exit.

dah.

### Generating Token Authentication

Token dapat mudah digenerate dengan `z3` algebra-solver.

```py
from z3 import *

# secret didapatkan pada binary.
secret = [
    0x12, 0x01, 0x12, 0x04,
    0x42, 0x14, 0x06, 0x1f,
    0x07, 0x16, 0x01, 0x10,
    0x40, 0x00, 0x00, 0x00
]

s = Solver()
t = [BitVec(f't!{i}', 32) for i in range(5)]

for i in range(len(t)):
    s.add(And(t[i] > 0x61, t[i] < 0x7a))

xored = 0
for i in range(len(t)):
    xored ^= t[i]

s.add((xored ^ secret[ 0]) + (xored ^ secret[ 1]) + (xored ^ secret[ 2]) == 308)
s.add((xored ^ secret[ 7]) + (xored ^ secret[ 8]) + (xored ^ secret[ 9]) == 325)
s.add((xored ^ secret[11]) + (xored ^ secret[12]) + (xored ^ secret[13]) == 265)

while s.check() == sat:
    m = s.model()

    for i in range(len(t)):
        s.add(Or(t[i] != m[t[i]]))

    token = ''.join([chr(m[i].as_long()) for i in t])
    token = f"{token[:3]}______{token[3]}___{token[4]}"

    print(token)
```

Jalankan dan akan mendapatkan banyak token yang bisa digunakan.

### Where is the bug?

Bug terdapat pada fungsi `edit`. Dimana index dari `message` yang akan di-edit tidak memiliki batas. Hal ini dapat menyebabkan index out-of-bound. Kita bisa mengedit pointer yang ada disebelum maupun sesudah `message_array`.

```c
if ( Arryindex )
{
    printf("Enter number to edit: ");
    scanf("%d[^\n]", &index);
    printf("Message Title: ");
    scanf(" %59[^\n]", message_array[index]); // oob jika 0 < index > 10
    printf("Message: ");
    message_content_ptr = message_array[index] + 60;
    scanf("%100[^\n]", message_content_ptr);
    fflush(stdin);
    fflush(stdout);
}
```

Sebagai gambaran, bersebelahannya variabel `message_array` dan `userinfo1`.

| Variable               | Value      |
| ---------------------- | ---------- |
| **message_array\[0\]** | 0x4072c0   |
| …                      | …          |
| **message_array\[9\]** | 0x00000000 |
| …                      | 0x00000000 |
| …                      | 0x00000000 |
| **userinfo1**          | “somename” |

Bagaimana jika `userinfo1` yang menyimpan inputan name kita berisi suatu alamat memori? dan kita mengedit message pada index 12? Maka nilai yang berada pada alamat tersebutlah yang akan diedit.

### GOT Hijacking

Proteksi yang terdapat pada binary.

```sh
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x3fd000)
RUNPATH:  b'/usr/local/bin/Nreport/libc/'
```

`RELRO` ini adalah suatu proteksi yang membuat suatu section pada binary menjadi read-only. Proteksi ini ada 2 mode: full dan partial.

- `Full` berarti GOT section memiliki permission read-only,
- `Partial` berarti GOT section memiliki permission writeable.

Untuk lainnya, cari sendiri :lol:

Karena binary memiliki address yang tetap (No PIE), artinya kita bisa mendapatkan alamat suatu simbol dari entry got dengan mudah. Dalam kasus ini, kita akan mengoverwrite `free@got` ke system. Dan melakukan free atau delete message yang mengandung string `"/bin/sh"` untuk mendapatkan shell.

### Exploit

Karena buffering enabled, maka disini aku hanya tuliskan alur exploitnya saja. Dan karena binary di-mesin memiliki setuid `root`, maka kita akan mendapatan `root`.

1.  Input valid token yang sudah didapat.
2.  Input name dengan alamat dari `free@got` yaitu `0x404018`.
3.  Create new message dengan dengan title dan content `"/bin/sh"`.
4.  Edit index 12 (OOB) yang akan menunjuk ke buffer name kita yang berisi alamat dari `free@got`, menjadi `system@plt` pada `0x401080`.
5.  Delete message index 0 tadi yang menyimpan string `"/bin/sh"` untuk men-trigger `free`.
6.  Root shell!
