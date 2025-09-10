; NtWriteVirtualMemory
; Arguments: rcx = ProcessHandle, rdx = BaseAddress, r8 = Buffer, r9 = Length
; Returns: rax = NTSTATUS

NtWriteVirtualMemory:
    mov r10, rcx            ; Save ProcessHandle
    mov r8, rdx             ; Save BaseAddress
    mov r9, r8              ; Save Buffer
    mov rdx, r9             ; Save Length
    mov rax, 0x1001         ; SSN for NtWriteVirtualMemory
    syscall
    ret
