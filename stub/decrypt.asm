struc WoodyData
    .text_entrypoint:   resq 1  ; 1x8 bytes
    .text_size:         resq 1  ; 1x8 bytes
    .key:               resb 16 ; 16x1 bytes
endstruc

; constants in .text section to simplify injection
section .text
    global _start

    WOODY:          db '....WOODY....', 10
    WOODY_LEN:      equ $-WOODY

    WOODY_DATA:
        dq 0xdeadbeefcafebabe   ; .text_entrypoint
        dq 0xdeadbeefcafebabe   ; .text_size
        times 16 db 0x42        ; .key

    ; syscalls
    SYS_WRITE:      equ 1
    SYS_MPROTECT:   equ 10
    SYS_EXIT:       equ 60

    ; mprotect flags
    PROT_READ:      equ 0x1
    PROT_WRITE:     equ 0x2
    PROT_EXEC:      equ 0x4

_start:
    mov rax, SYS_WRITE
    mov rdi, 1
    mov rsi, WOODY
    mov rdx, WOODY_LEN
    syscall

    mov rax, [WOODY_DATA + WoodyData.text_entrypoint]
    jmp rax
