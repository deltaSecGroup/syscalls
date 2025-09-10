; NtAllocateVirtualMemory
; Arguments: rcx = ProcessHandle, rdx = BaseAddress, r8 = ZeroBits, r9 = RegionSize, r10 = AllocationType, r11 = Protect
; Returns: rax = NTSTATUS

NtAllocateVirtualMemory:
    mov r10, rcx            ; Save ProcessHandle
    mov r8, rdx             ; Save BaseAddress
    mov r9, r8              ; Save ZeroBits
    mov rdx, r9             ; Save RegionSize
    mov r8, r10             ; Save AllocationType
    mov r9, r8              ; Save Protect
    mov rax, 0x1002         ; SSN for NtAllocateVirtualMemory
    syscall
    ret
