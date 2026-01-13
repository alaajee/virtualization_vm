# ScratchVM: Lab 1 - ANSWERS

The objective of this first lab is to be able to run a binary code inside a micro virtual machine by completing the function called in the [main.c](vm_src/src/main.c) file.
Our virtual machine contains 1 vCPU and low amount of physical memory. We do not consider devices (disk, network, peripherals, ...).
The main.c file (and all the called functions) is the Virtual Machine Monitor code.

## Step 0: Taking control of KVM 
* Browse the [KVM API documentation](https://www.kernel.org/doc/Documentation/virt/kvm/api.txt)

KVM is the Linux module that acts as a hypervisor providing virtualization services for managing virtual machines.
KVM provides many services for virtual machine management.
Each service is associated to a component (virtual machine, virtual CPU, ...) which the service operation is applied on.
To perform such operation with KVM, the application has to call the ioctl system call with the corresponding file descriptor component.

For instance, KVM_GET_LAPI reads the Local APIC registers of the given vCPU and copies them into the input argument.
```
4.57 KVM_GET_LAPIC

Capability: KVM_CAP_IRQCHIP
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_lapic_state (out)
Returns: 0 on success, -1 on error

#define KVM_APIC_REG_SIZE 0x400
struct kvm_lapic_state {
	char regs[KVM_APIC_REG_SIZE];
};
```
The application code should be:

```c
struct kvm_lapic_state lapic;
int ret = ioct(vcpu_fd, KVM_GET_LAPIC, &lapic);
```

The following ioctl needed for:

* Creating a virtual machine and virtual CPU,
```
KVM_CREATE_VM: Returns a VM file descriptor that can be used to control the new virtual machine. The new VM has no virtual cpus and no memory.
KVM_CREATE_VCPU: Returns a vcpu file descriptor on success, -1 on error. This API adds a vcpu to a virtual machine.
```
* Accessing the virtual CPU registers
```
KVM_GET_REGS: Reads the general purpose registers from the vcpu copies them into the input argument.
KVM_SET_REGS: Writes the general purpose registers into the vcpu from the input argument.
```
* Allocating guest physical memory
```
KVM_SET_USER_MEMORY_REGION: This ioctl allows the user to create, modify or delete a guest physical memory slot.
```
* Running the VM
```
KVM_RUN: This ioctl is used to run a guest virtual cpu.
```

## Step 1: Creating a simple virtual machine
- Create th KVM virtal machine -- create_vm() in [manager.c:12](vm_manager/manager.c)

```c
int create_vm(void)
{
    int ret = -1;
    /* We first open a file descriptor to communication with KVM module */
    ret = open("/dev/kvm", O_RDWR);
    if (ret == -1)
        errx(1, "KVM open failed");
    kvmfd = ret;

    /* We can now create an empty virtual machine by calling KVM_CREATE_VM ioctl */
    ret = ioctl(kvmfd, KVM_CREATE_VM, 0);
    if (ret == -1)
        errx(1, "KVM_CREATE_VM failed");
    vmfd = ret;
    return 0;
}
```
- Create 1 virtual CPU -- create_bootstrap() in [manager.c:32](vm_manager/manager.c)
```c
int create_bootstrap()
{
    struct kvm_sregs sregs;
    size_t mmap_size;
    int ret = -1;
    int nent = 128;
    struct kvm_cpuid2 *cpuid2 = (struct kvm_cpuid2 *)malloc(sizeof(struct kvm_cpuid2) + nent * sizeof(struct kvm_cpuid_entry2));
    cpuid2->nent = nent;
    if (ioctl(kvmfd, KVM_GET_SUPPORTED_CPUID, cpuid2) < 0)
        err(1, "cant get cpuid");

    /* We add a new virtual CPU to the VM */ 
    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);

    if (vcpufd == -1)
        err(1, "Cannot create vcpu\n");

    if (ioctl(vcpufd, KVM_SET_CPUID2, cpuid2) < 0)
        err(1, "cannot set cpuid things\n");

    ret = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret == -1)
        err(1, "KVM_GET_VCPU_MMAP_SIZE");
    mmap_size = ret;
    if (mmap_size < sizeof(*run))
        errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
    run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
    if (!run)
        err(1, "mmap vcpu");

    ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_SET_SREGS");
    return ret;
}
```



## Step 2: Loading the binary code
- Allocate guest physical memory -- create_guest_physical_memory(size) in [manager.c:25](vm_manager/manager.c)

```c
int create_guest_physical_memory(size_t size)
{
    int ret = -1;
    /* We first allocate host virtual memory */
    memory = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);


    struct kvm_userspace_memory_region region =
        {
            /* This slot is the number 0 (the first) */
            .slot = 0,

            /* The guest physical starting address of this physical space is 0 in the guest point of view */
            .guest_phys_addr = 0,

            /* The size of the guest physical is size given as argument of the function  */
            .memory_size = size,

            /* The host virtual address associated corresponds to the virtual memory allocated with mmap */
            .userspace_addr = (uint64_t)memory,
        };

    /* KVM create a new slot based on the information given above */
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);

    return ret;
}
```


- Copy the code in the guest physical memory area -- load_vm_code(code) in [loader.c:93](load_manager/loader.c)
```c
int load_vm_code(const uint8_t *code)
{
    uint8_t *mem = get_memory();

    /* The code is loaded at the physical address 0x1000 */
    memcpy(&mem[0x1000], code, 12);
    return 0;
}
```


## Step 3: Running the virtual machine
- Update the vCPU registers -- launch_vm() in [manager:84-86](vm_manager/manager.c)
```c
int launch_vm()
{
    int ret;
    struct kvm_regs regs;
    ioctl(vcpufd, KVM_GET_REGS, &regs);

    /* Update Of The vCPU Registers - RAX, RBX and RIP */
    regs.rflags = 2;

    /* The code calculates the sum of RAX and RBX registers */
    regs.rax = 4;
    regs.rbx = 2;

    /* Since the code is located at the guest physical address 0x1000,
    the RIP register must be 0x1000.
    */
    regs.rip = 0x1000;
    ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
    ...
```

- Run the vCPU
```c
    ...
    /* It is required to call KVM_RUN in a infinite loop since the VM should run until the VMM decide to exit it */
    while(1)
    {
        /* To deploy a VM, it necessary to call KVM_RUN ioctl on each virtual CPU -- in our case, the VM has just one vCPU.
            Starting from this ioctl call, the VM runs.
        */
        if (ioctl(vcpufd, KVM_RUN, NULL) == -1)
            err(1, "KVM_RUN");

        /* The VM exits here due to some instructions (VMExit).
            The VMM has to handle each VMExit (emulation, virtualization, or else).
        */
        vmexit_handler(run->exit_reason)
    }
```


## Step 4: Deploying the VM
- Run the VM
```bash 
$ cd lab_1/vm_src
$ make all && make run
```
You should have this output
```bash
6
KVM_EXIT_HLT
```
