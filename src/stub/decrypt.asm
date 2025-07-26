ENTRYPOINT_MARKER: equ 0x4242424242424242
MPROTECT_ADDR_MARKER: equ 0x6969696969696969
DECRYPT_START_OFFSET_MARKER: equ 0x6666666666666666
DECRYPT_LEN_MARKER: equ 0x3333333333333333

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

    jmp jmp_to_original_code

    mov rax, SYS_EXIT
    mov rdi, 0
    syscall

get_base:
    xor rax, rax
    xor rdi, rdi

    xor rsi, rsi ; O_RDONLY
    lea rdi, [rel proc_file_path]
    mov rax, SYS_OPEN
    syscall

    cmp eax, 0
    jl error

    push rax ; save fd

    xor r10, r10
    xor r8, r8
    xor rdi, rdi
    xor rbx, rbx
    xor rdx, rdx

    sub sp, 16 ; allocate 16 bytes on the stack for buffer

    ; int read(int fd, void* buf, int n)
    mov rdx, 1 ; n
    lea rsi, [rsp] ; *buf
    mov edi, eax ; fd

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

error:
    mov rax, SYS_EXIT
    mov rdi, 1
    syscall

jmp_to_original_code:
    mov rdi, ENTRYPOINT_MARKER
    add rdi, rbx
    jmp rdi

woody_string:
    db "....WOODY....",10
proc_file_path:
    db "/proc/self/maps",0
