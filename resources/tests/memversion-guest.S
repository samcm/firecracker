/* SPDX-License-Identifier: Apache-2.0 */
/* x86_64 Linux-boot ELF; no stack, interrupts, OS, disk or network. */
/* Build: cc -nostdlib -static -Wl,-N,-Ttext=0x100000,-e,_start,--build-id=none
 *        resources/tests/memversion-guest.S -o build/compatibility/memversion-guest.elf */
.global _start
.section .text
.code64

.macro byte value
    mov $0x3fd, %dx
1:  in %dx, %al
    test $0x20, %al
    jz 1b
    mov $0x3f8, %dx
    mov $\value, %al
    out %al, %dx
.endm
.macro prefix
    byte 77
    byte 86
    byte 71
    byte 32
.endm
.macro verified
    prefix
    byte 86
    byte 69
    byte 82
    byte 73
    byte 70
    byte 73
    byte 69
    byte 68
    byte 10
.endm

_start:
    cli
    cld
    xor %r12, %r12
    mov $0x400000, %edi
    mov $2048, %ecx
    movabs $0x3535353535353535, %rax
    rep stosq
    prefix
    byte 82
    byte 69
    byte 65
    byte 68
    byte 89
    byte 10
poll:
    mov $0x3fd, %dx
    in %dx, %al
    test $1, %al
    jz poll
    mov $0x3f8, %dx
    in %dx, %al
    cmp $119, %al /* w: modify precisely two already-present pattern pages */
    je write
    cmp $118, %al /* v: verify without any guest-memory write */
    jne poll
    jmp verify
write:
    mov $0x400000, %edi
    mov $1024, %ecx
    movabs $0xa7a7a7a7a7a7a7a7, %rax
    rep stosq
    mov $1, %r12
verify:
    mov $0x400000, %edi
    mov $2048, %ecx
check:
    movabs $0x3535353535353535, %rbx
    test %r12, %r12
    jz compare
    cmp $0x402000, %edi
    jae compare
    movabs $0xa7a7a7a7a7a7a7a7, %rbx
compare:
    cmp %rbx, (%rdi)
    jne failed
    add $8, %edi
    loop check
    verified
    jmp poll
failed:
    prefix
    byte 70
    byte 65
    byte 73
    byte 76
    byte 10
    jmp failed
.section .note.GNU-stack,"",@progbits
