ENTRYPOINT_MARKER: equ 0x4242424242424242
MPROTECT_SIZE_MARKER: equ 0x2424242424242424
MPROTECT_ADDR_MARKER: equ 0x6969696969696969
XOR_KEY: equ 0x1111111111111111

SYS_WRITE: equ 1
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

    call get_string_addr

woody_string:
    db '....WOODY....', 10

get_string_addr:
    pop rsi                     ; rsi -> woody_string
    mov rdx, 14
    syscall

    pop rdx
    pop rsi
    pop rdi
    pop rax

    call start_decryption

start_decryption:
    push rax
    push rdi
    push rsi
    push rdx

    mov rax, SYS_MPROTECT
    mov rdi, MPROTECT_ADDR_MARKER
    mov rsi, MPROTECT_SIZE_MARKER
    mov rdx, PROT_READ | PROT_WRITE | PROT_EXEC
    syscall

    test rax, rax
    js error

    pop rdx
    pop rsi
    pop rdi
    pop rax

    push rax
    push rdi
    push rsi
    push rdx
    push r8
    push r9
    push r10

    mov rsi, MPROTECT_ADDR_MARKER
    mov rcx, MPROTECT_SIZE_MARKER
    mov rdx, 0 ; counter
    mov r8, 0

xor_loop:
    cmp rdx, rcx
    jge call_original_code

    mov r9b, [rsi + rdx]

    xor r9b, 0x01
    xor r9b, 0x01

    mov [rsi + rdx], r9b

    inc rdx
    inc r8
    and r8, 0x3f
    jmp xor_loop

call_original_code:
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rsi
    pop rdi
    pop rax

    mov rax, ENTRYPOINT_MARKER
    jmp rax

error:
    mov rax, SYS_EXIT
    mov rdi, 1
    syscall
