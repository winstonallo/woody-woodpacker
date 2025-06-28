SYS_WRITE: equ 1

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

    mov rax, 0x4242424242424242
    jmp rax
