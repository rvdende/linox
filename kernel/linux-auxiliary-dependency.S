.intel_syntax noprefix
.section .text
.global linox_auxiliary_symbol
.type linox_auxiliary_symbol,@function
.Lauxiliary_local:
linox_auxiliary_symbol:
    cmp qword ptr [rip + .Lauxiliary_initialized], 0x4758
    jne .Lauxiliary_uninitialized
    movabs rax, 0x5952414958554147
    ret
.Lauxiliary_uninitialized:
    xor eax, eax
    ret

.global linox_auxiliary_init
.hidden linox_auxiliary_init
.type linox_auxiliary_init,@function
linox_auxiliary_init:
    cmp qword ptr [0x405008], 1
    jne .Lauxiliary_init_done
    mov rdx, qword ptr [rip + linox_auxiliary_tls_template@GOTTPOFF]
    movabs rax, 0x0a21534c54585541
    cmp qword ptr fs:[rdx], rax
    jne .Lauxiliary_init_done
    cmp qword ptr fs:[rdx + 8], 0
    jne .Lauxiliary_init_done
    mov qword ptr [rip + .Lauxiliary_initialized], 0x47
.Lauxiliary_init_done:
    ret

.Lauxiliary_initialize:
    cmp qword ptr [rip + .Lauxiliary_initialized], 0x47
    jne .Lauxiliary_initialize_done
    cmp edi, 1
    je .Lauxiliary_initialize_single_vector
    cmp edi, 2
    jne .Lauxiliary_initialize_done
    cmp qword ptr [rsi + 16], 0
    jne .Lauxiliary_initialize_done
    cmp qword ptr [rdx + 16], 0
    jne .Lauxiliary_initialize_done
    mov rax, qword ptr [rsi + 8]
    movabs rcx, 0x2d63696d616e7964
    cmp qword ptr [rax], rcx
    jne .Lauxiliary_initialize_done
    cmp dword ptr [rax + 8], 0x63657865
    jne .Lauxiliary_initialize_done
    cmp byte ptr [rax + 12], 0
    jne .Lauxiliary_initialize_done
    mov rax, qword ptr [rdx]
    movabs rcx, 0x00313d584f4e494c
    cmp qword ptr [rax], rcx
    jne .Lauxiliary_initialize_done
    mov rax, qword ptr [rdx + 8]
    movabs rcx, 0x4f4d5f584f4e494c
    cmp qword ptr [rax], rcx
    jne .Lauxiliary_initialize_done
    movabs rcx, 0x00636578653d4544
    cmp qword ptr [rax + 8], rcx
    jne .Lauxiliary_initialize_done
    jmp .Lauxiliary_initialize_common
.Lauxiliary_initialize_single_vector:
    cmp qword ptr [rsi + 8], 0
    jne .Lauxiliary_initialize_done
    cmp qword ptr [rdx + 8], 0
    jne .Lauxiliary_initialize_done
.Lauxiliary_initialize_common:
    mov rax, qword ptr [rsi]
    cmp dword ptr [rax], 0x696e692f
    jne .Lauxiliary_initialize_done
    cmp word ptr [rax + 4], 0x74
    jne .Lauxiliary_initialize_done
    mov rax, qword ptr [rdx]
    movabs rcx, 0x00313d584f4e494c
    cmp qword ptr [rax], rcx
    jne .Lauxiliary_initialize_done
    mov qword ptr [rip + .Lauxiliary_initialized], 0x4758
.Lauxiliary_initialize_done:
    ret

.Lauxiliary_anchor:
    mov rax, qword ptr [rip + linox_auxiliary_symbol@GOTPCREL]
    call linox_auxiliary_symbol@PLT
    ret

.section .init_array,"aw",@init_array
    .quad .Lauxiliary_initialize

.section .data,"aw",@progbits
.Lauxiliary_initialized:
    .quad 0

.section .tdata,"awT",@progbits
.balign 8
.global linox_auxiliary_tls_template
.hidden linox_auxiliary_tls_template
linox_auxiliary_tls_template:
    .ascii "AUXTLS!\n"

.section .tbss,"awT",@nobits
.balign 8
.global linox_auxiliary_tls_zero
.hidden linox_auxiliary_tls_zero
linox_auxiliary_tls_zero:
    .space 8
