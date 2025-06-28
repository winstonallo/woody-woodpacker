struc WoodyData
    .text_entrypoint:   resq 1  ; 1x8 bytes
    .text_size:         resq 1  ; 1x8 bytes
    .key:               resb 16 ; 16x1 bytes
endstruc


; syscalls
SYS_WRITE:      equ 1
SYS_MPROTECT:   equ 10
SYS_EXIT:       equ 60

; mprotect flags
PROT_READ:      equ 0x1
PROT_WRITE:     equ 0x2
PROT_EXEC:      equ 0x4

_start:
    push rax
    push r8
    push rdi
    push rsi
    push rdx
    push rcx
    call call_original_code

print_woody:
    mov rax, SYS_WRITE
    mov rdi, 1
    mov rsi, WOODY
    mov rdx, WOODY_LEN
    syscall
    ret

decrypt:
    mov rax, SYS_MPROTECT
    mov rdi, [WOODY_DATA + WoodyData.text_entrypoint]
    mov rsi, [WOODY_DATA + WoodyData.text_size]
    mov rdx, PROT_WRITE
    or rdx, PROT_READ
    syscall

    test rax, rax
    js error

    mov rsi, [WOODY_DATA + WoodyData.text_entrypoint]
    mov rcx, [WOODY_DATA + WoodyData.text_size]
    mov rdx, 0  ; counter
    mov r8, 0   ; key index

xor_loop:
    ; if (counter >= text_size) { ... }
    cmp rdx, rcx
    jge decrypt_done

    ; uint8_t byte_to_encrypt = text[*rdx]
    mov al, [rsi + rdx]

    ; uint8_t key_byte = key[*r8]
    mov dl, [WOODY_DATA + WoodyData.key + r8]

    ; byte_to_encrypt ^= key_byte
    xor al, dl

    ; text[*rdx] = byte_to_encrypt
    mov [rsi + rdx], al
    inc rdx
    inc r8

    cmp r8, 16
    jl xor_loop
    mov r8, 0
    jmp xor_loop

decrypt_done:
    mov rax, SYS_MPROTECT
    mov rdi, [WOODY_DATA + WoodyData.text_entrypoint]
    mov rsi, [WOODY_DATA + WoodyData.text_size]
    mov rdx, PROT_READ
    or rdx, PROT_EXEC
    syscall

    ret

call_original_code:
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax
    pop r8
    mov rax, qword 0x401020
    jmp rax

error:
    mov rax, SYS_WRITE
    mov rdi, 2
    mov rsi, ERROR_MSG
    mov rdx, ERROR_MSG_LEN
    syscall

    mov rax, SYS_EXIT
    mov rdi, 1
    syscall



ERROR_MSG:      db 'Error', 10
ERROR_MSG_LEN:  equ $-ERROR_MSG

WOODY:          db '....WOODY....', 10
WOODY_LEN:      equ $-WOODY

WOODY_DATA:
    dq 0xdeadbeefcafebabe   ; .text_entrypoint
    dq 0xcafebabedeadbeef   ; .text_size
    times 16 db 0x42        ; .key
