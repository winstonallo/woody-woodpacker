ENTRYPOINT_MARKER: equ 0x4242424242424242
MPROTECT_ADDR_MARKER: equ 0x6969696969696969
DECRYPT_START_OFFSET_MARKER: equ 0x6666666666666666
DECRYPT_LEN_MARKER: equ 0x3333333333333333
IS_PIE: equ 0x2424242424242424

SYS_READ: equ 0
SYS_WRITE: equ 1
SYS_OPEN: equ 2
SYS_CLOSE: equ 3
SYS_MPROTECT: equ 10
SYS_EXIT: equ 60

PROT_READ: equ 0x01
PROT_WRITE: equ 0x02
PROT_EXEC: equ 0x04

_start:
    push rax
    push rdi
    push rsi
    push rdx

    mov rax, SYS_WRITE
    mov rdi, 1
    lea rsi, [rel woody_string]
    mov rdx, 14
    syscall

    call get_base

    pop rdx
    pop rsi
    pop rdi
    pop rax

    ;jmp jmp_to_original_code
    jmp start_decryption

    mov rax, SYS_EXIT
    mov rdi, 0
    syscall

get_base:
    push r15
    mov r15, IS_PIE
    cmp r15, 0

    je non_pie

    pop r15

    xor rax, rax
    xor rdi, rdi

    mov rsi, 0 ; O_RDONLY
    lea rdi, [rel proc_file_path]
    mov rax, SYS_OPEN
    syscall

    cmp eax, 0
    jl error

    push rax ; fd

    xor r10, r10
    xor r8, r8
    xor rdi, rdi
    xor rbx, rbx
    xor rdx, rdx

    sub sp, 16 ; 16 bytes stack buffer

    mov rdx, 1
    lea rsi, [rsp]
    mov edi, eax

read_proc_map:
    ; read one byte
    mov rax, SYS_READ
    syscall

    cmp BYTE [rsp], '-'
    je break
    inc r10b
    mov r8b, BYTE [rsp]

    cmp r8b, '9'
    jle num

alpha:
    sub r8b, 0x57
    jmp load

num:
    sub r8b, '0'

load:
    shl rbx, 4
    or rbx, r8
    add rsp, 1
    lea rsi, [rsp]
    jmp read_proc_map

break:
    sub sp, r10w
    add sp, 16

    ; close(fd)
    pop rdi
    mov rax, SYS_CLOSE
    syscall

    ret

non_pie:
   mov rbx, 0 ; base address for non-PIE
   pop r15
   ret

start_decryption:
    push rax
    push rdi
    push rsi
    push rdx

    mov rax, SYS_MPROTECT
    mov rdi, DECRYPT_START_OFFSET_MARKER
    add rdi, rbx
    and rdi, ~0xfff ; page alignment
    mov rsi, DECRYPT_LEN_MARKER
    add rsi, 0xfff
    mov rdx, PROT_READ | PROT_WRITE | PROT_EXEC
    syscall

    test rax, rax
    js error

    ;jmp jmp_to_original_code

    push r8
    push r9
    push r10
    push r11

    lea r11, [rel xor_key]
    mov rsi, DECRYPT_START_OFFSET_MARKER
    add rsi, rbx ; add base address
    mov rcx, DECRYPT_LEN_MARKER
    mov rdx, 0
    mov r8, 0

xor_loop:
    cmp rdx, rcx
    jge jmp_to_original_code

    mov r9b, [rsi + rdx]
    mov r10b, [r11 + r8]

    xor r9b, r10b
    ;xor r9b, r10b
    mov [rsi + rdx], r9b

    inc rdx
    inc r8
    and r8, 0xf
    jmp xor_loop


error:
    mov rax, SYS_EXIT
    mov rdi, 1
    syscall

jmp_to_original_code:
    mov rax, SYS_MPROTECT
    mov rdi, DECRYPT_START_OFFSET_MARKER
    add rdi, rbx
    and rdi, ~0xfff
    mov rsi, DECRYPT_LEN_MARKER
    add rsi, 0xfff ; padding
    mov rdx, PROT_READ | PROT_EXEC
    syscall

    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rsi
    pop rdi
    pop rax

    mov rdi, ENTRYPOINT_MARKER
    add rdi, rbx
    jmp rdi

woody_string:
    db "....WOODY....",10
proc_file_path:
    db "/proc/self/maps",0
xor_key:
   db 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
