# ScratchVM: Lab 2 -- ANSWERS

The objective of this second lab is to run a simple Linux C application inside a micro virtual machine.
This virtual machine is composed of 1 vCPU and low amount of physical memory. We do not consider devices (disk, network, peripherals, ...).


## Step 1: Understanding VM application execution flow 
- Deploy and run the virtual machine and describe what you observe (the output).
```bash
$ cd lab2/vm_src
$ make alll && make run
```
The application is stucked in an infinite loop and prints "KVM_EXIT_HLT".

- Study and try to explain the VM application execution flow. (Check the files [boot.asm](./vm_src/src/boot.asm) and [manager.c](./vm_manager/manager.c))

We remind you that for running the virtual machine, the VMM calls the KVM_RUN ioctl on the bootstrap vCPU in an infinite loop.
The messsage "KVM_EXIT_HLT" is printed by the VMM in the function vm_exit_handler.
That means that the virtual machine triggered a VM exit due to the "hlt" instruction.
(In virtualized mode, some instructions trigger VM exit handled by the hypervisor.)
After handling the VM exit by printing the message, the VMM resumes the VM execution.

## Step 2: Handling VM exits
- Explain the meaning of the VM exit.

Classical Linux C application performs system call handled by the Operating System (system call handler).
If you take a look at the VMM code (manager.c), it only loads the boot (compiled file of boot.asm) and the application codes.
The boot.asm file corresponds to the bootstrap procedure of the bootsrap vCPU.
This procedure is executed at vCPU startup and is required to update vCPU state from 16bits Real Mode to 64bits paging mode before running the application in user mode ([16bits Real Mode](https://wiki.osdev.org/Real_Mode) - [64bits Long Mode](https://wiki.osdev.org/X86-64)).
It is also used as a kernel, in particular for system call requests of the user application (boot.asm:85).
Each time the user application requests a system call (executing the "syscall" instruction), the vCPU switches from user to kernel mode and jump to the syscall handler.
The latter performs no operation, it just forwards the system call request by triggering a VM exit KVM_EXIT_HLT (due to the "hlt" instruction).
To conclude, the VM exits observed in the previous step correspond to system calls of the VM application.

**NB: Triggering a VM exit for each syscall performed in the guest is not necessarily mandatory and is a choice made here given the (simple) configuration used for this practical assignment. In other words, in the case of a guest with user/kernel separation, syscalls could be handled without necessarily triggering VM exits.**

- Identify and detail these operations. ([Linux System Call Table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/))

The system calls requested by the VM application are in order:
1. **sys_arch_prctl**
    * **int** syscall(SYS_arch_prctl, int **op**, unsigned long **addr**);
    * sets architecture-specific process or thread state. **op** selects an operation and passes argument **addr** to it.
    * returns 0 on success, -1 on error.

2. **sys_set_tid_address** 
    * **int** syscall(SYS_set_tid_address, int ***tidptr**); 
    * sets the **clear_child_tid** value for the calling thread to **tidptr**.
    * returns the caller's thread ID.

3. **sys_open**
    * **int** open(const char **path**, int **flags**, ... /* mode_t **mode** */ );
    * opens the file specified by **path**. It returns the new file descriptor.
    * return the new file descriptor.

4. **sys_write** (2x)
    * **ssize_t** write(int **fd**, const void **buf[count]**, size_t **count**);
    * writes up to **count** bytes from the buffer starting at **buf** to the file referred to by the file descriptor **fd**.
    * returns the number of bytes written on success, -1 on error.

5. **sys_close**
    * **int** close(int **fd**);
    * closes the file descriptor fd, so that it no longer refers to  any file and may be reused.
    * returns 0 on success, -1 on error.

6. **sys_exit_group**
    * **[[noreturn]] void** syscall(SYS_exit_group, int **status**);
    * terminates all threads in the calling process's thread group

7. **sys_exit**
    *  **[[noreturn]] void** _exit(int **status**);
    * terminates the calling process "immediately".

The system calls sys_arch_prctl, sys_set_tid_address and sys_exit_group are used to maintain consistency in linux environment. In our case, they ar useless since the virtual machine does not contain any operating system.

- Handle the operations performed by the VM application.

For handling, we can point 4 steps:
1. Identify the system call number
    * read the vCPU reigister RAX
    * dispatch the handler depending on the RAX value

2. Retrieve the arguments
    * determine the number of arguments and read the corresponding vCPU registers
    * translate guest address to host address

3. Performing the corresponding system call
    * call the right system call with the correct argument (host point of view)
    * return the system call return value -- update the RAX register.
```c
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
        printf("WRITE %lld %llx %lld - return %lld\n", arg1, arg2, arg3, regs.rax);
        break;
    case 2: /* open */
        /* The same operation is applied to obtain the HVA of the path */
        char *path = &mem[arg1];
        regs.rax = open(path, arg2, arg3);
        printf("OPEN %s %lld %lld - return %lld\n", path, arg2, arg3, regs.rax);
        break;
    case 3: /* close */
        regs.rax = close(arg1);
        printf("CLOSE %lld - return %lld\n", arg1, regs.rax);
        break;
    case 60: /* exit */
        printf("EXIT %lld\n", arg1);
        exit(arg1);
        break;
    case 158: /* arch_prctl - USELESS HERE */
        break;
    case 218: /* set_tid_address - USELESS HERE */
        break;
    case 231: /* exit_group - USELESS HERE */
        break;
    default:
        printf("undefind syscall %lld\n", regs.rax);
        break;
    }

    /* Update the vCPU register for the system calls return values */
    ioctl(vcpufd, KVM_SET_REGS, &regs);
    return 1;
}
```

## Step 3: Reverse Engineering
- Try to guess the source code of the VM application.

Based on the system call requests of the VM application, we can guess the application source code:
```c
char *buff_1 = "Hello World !!!\n";
char *buff_2 = "Bye Bye !!!\n";

#define FILENAME "./ay_caramba"

int main(void)
{
    int fd = open(FILENAME, O_RDWR | O_CREAT, 0777);
    write(fd, buff_1, strlen(buff_1));
    write(fd, buff_2, strlen(buff_2));
    close(fd);
    return 0;
}
```

