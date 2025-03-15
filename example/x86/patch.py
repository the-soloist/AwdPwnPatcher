#!/usr/bin/env python
# coding=utf-8

from pwn import *
from AwdPwnPatcher import *
import lief


binary = "./vuln64"
patcher = AwdPwnPatcher(binary)
# fmt_offset = patcher.add_constant_in_ehframe("%s\x00\x00")
# assembly = """
# mov rsi, rax
# lea rdi, qword ptr [{}]
# """.format(hex(fmt_offset))
# patcher.patch_by_jmp(0xbd4, jmp_to=0xbdc, assembly=assembly)

# assembly = """
# mov edx, 0x20
# """
# patcher.patch_origin(0x9db, end=0x9e0, assembly=assembly)

# assembly = """
# lea rax, qword ptr [rdx + rax]
# mov rdi, qword ptr [rax]
# mov qword ptr [rax], 0
# """
# patcher.patch_by_jmp(0xb7e, jmp_to=0xb85, assembly=assembly)
patcher._eh_frame_add_execute_permission()
patcher.save()


# context.arch = 'amd64'
# binary_1 = lief.parse('./vuln64')
# # shellcode = asm("mov rsi,0 \nmov rdx,0\nmov rax,59\nsyscall")
# # print(shellcode)
# # rdi,rsi,rdx

# # eh_frame = binary_1.get_section(".eh_frame")  # 拿到section后写入
# # content = list(shellcode + b'0' * (eh_frame.size - len(shellcode)))
# # eh_frame.content = content
# eh_frame_seg = binary_1.segments[6]  # 04段
# eh_frame_seg.flags = lief.ELF.Segment.FLAGS(7)  # 修改权限
# printf_sym = binary_1.get_symbol("printf")
# # binary_1.patch_pltgot('printf', eh_frame.virtual_address)  # 把printf符号的值patch掉

# binary_1.write("./vuln64_patched")
