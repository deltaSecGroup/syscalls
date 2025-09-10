; NtCreateThreadEx
; Arguments: rcx = ThreadHandle, rdx = DesiredAccess, r8 = ObjectAttributes, r9 = ProcessHandle, r10 = StartAddress, r11 = StartParameter, r12 = CreateFlags, r13 = ZeroBits, r14 = StackSize, r15 = MaximumStackSize
; Returns: rax = NTSTATUS

NtCreateThreadEx:
    mov r10, rcx            ; Save ThreadHandle
    mov r8, rdx             ; Save DesiredAccess
    mov r9, r8              ; Save ObjectAttributes
    mov rdx, r9             ; Save ProcessHandle
    mov r8, r10             ; Save StartAddress
    mov r9, r8              ; Save StartParameter
    mov r10, r9             ; Save CreateFlags
    mov r11, r10            ; Save ZeroBits
    mov r12, r11            ; Save StackSize
    mov r13, r12            ; Save MaximumStackSize
    mov r14, r13            ; Save MaximumStackSize
    mov r15, r14            ; Save MaximumStackSize
    mov rax, 0x1004         ; SSN for NtCreateThreadEx
    syscall
    ret
