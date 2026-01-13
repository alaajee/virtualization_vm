#define _GNU_SOURCE
#include "syscall_handler.h"

int syscall_handler(uint8_t *memory, int vcpufd)
{
    struct kvm_regs regs;
    int ret = -1;

    /* Read the vCPU registers */
    ioctl(vcpufd, KVM_GET_REGS, &regs);

    /* Read the system call arguments */
    __u64 arg1 = regs.rdi;
    __u64 arg2 = regs.rsi;
    __u64 arg3 = regs.rdx;
    __u64 arg4 = regs.r10;
    __u64 arg5 = regs.r8;
    __u64 arg6 = regs.r9;

    /** Get the guest physical memory for translation.
     * NB: for simplicity, we implemented an identity guest page table,
     * it means that a X guest virtual page is mapped on the X guest physical page.
     */

    uint8_t *mem = get_memory();

    /* The system call number is stored in the RAX register*/
    switch (regs.rax)
    {
    case 1: /* write */
        /**
         * The 2nd argument is a pointer to a string.
         * This pointer corresponds to a guest virtual address (GVA).
         * From the VMM, we have to translate the GVA to host virtual address (HVA).
         * For a given GVA X, the corresponding HVA is MEM+GVA
         * (MEM is the address of the mmap performed by the VMM to allocate guest physical memory).
         */
        char *buff = &mem[arg2];
        regs.rax = write(arg1, buff, arg3);
        printf("VM_APP - WRITE %lld %llx %lld - return %lld\n", arg1, arg2, arg3, regs.rax);
        break;
    case 2: /* open */
        /* The same operation is applied to obtain the HVA of the path */
        char *path = &mem[arg1];
        regs.rax = open(path, arg2, arg3);
        printf("VM_APP - OPEN %s %lld %lld - return %lld\n", path, arg2, arg3, regs.rax);
        break;
    case 3: /* close */
        regs.rax = close(arg1);
        printf("VM_APP - CLOSE %lld - return %lld\n", arg1, regs.rax);
        break;
    case 60: /* exit */
        printf("VM_APP - EXIT %lld\n", arg1);
        exit(arg1);
        break;  
    case 999: // SAVE
        printf("SAVE OPERATION\n");
        dump();
        break;
    case 158: /* arch_prctl - USELESS HERE */
        break;
    case 218: /* set_tid_address - USELESS HERE */
        break;
    case 231: /* exit_group - USELESS HERE */
        break;
    default:
        printf("VM_APP - undefind syscall %lld\n", regs.rax);
        break;
    }

    /* Update the vCPU register for the system calls return values */
    ioctl(vcpufd, KVM_SET_REGS, &regs);
    return 1;
}