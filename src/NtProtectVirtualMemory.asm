; NtProtectVirtualMemory
; Arguments: rcx = ProcessHandle, rdx = BaseAddress, r8 = RegionSize, r9 = NewProtect
; Returns: rax = NTSTATUS

NtProtectVirtualMemory:
    mov r10, rcx            ; Save ProcessHandle
    mov r8, rdx             ; Save BaseAddress
    mov r9, r8              ; Save RegionSize
    mov rdx, r9             ; Save NewProtect
    mov r8, r10             ; Save OldProtect
    mov r9, r8              ; Save OldProtect
    mov rax, 0x1003         ; SSN for NtProtectVirtualMemory
    syscall
    ret
