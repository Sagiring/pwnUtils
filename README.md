# pwnUtils
基于pwntools
整合一些有用的pwn板子
### def show_addr(name,addr) 
打印地址

### recv_addr(r:process,name:str,until:bytes =b'\x7f',offset:int = 0,junkUntil:bytes = b'',recvType:str = 'bytes')->int
接收地址

### setcontext_orw(libc:elf,orw_addr:int,rdi_addr:int)
打setcontext_orw,输出orw_payload,rdi_payload

### house_of_cat(libc:elf,fakeio_addr:int)
打house_of_cat,输出fakeio
