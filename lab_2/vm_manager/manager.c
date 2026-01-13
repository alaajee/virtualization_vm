#include "manager.h"

int kvmfd, vmfd, vcpufd;
struct kvm_run *run;
uint8_t *memory;
int slot_id = 0;
int create_vm(void)
{
    int ret;

    /* Getting the KVM File Descriptor */
    kvmfd = open("/dev/kvm", O_RDWR);
    if (kvmfd == -1)
        err(1, "/dev/kvm");
    ret = ioctl(kvmfd, KVM_GET_API_VERSION, NULL);
    if (ret == -1)
        err(1, "KVM_GET_API_VERSION");

    /* Creating A VM Structure */
    vmfd = ioctl(kvmfd, KVM_CREATE_VM, (unsigned long)0);
    if (vmfd == -1)
        err(1, "KVM_init_vm");
    return 0;
}
int add_memory(size_t size, uint64_t start)
{
    int ret = -1;
    /* Allocating The Guest Physical Memory */
    memory = (uint8_t *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!memory)
        err(1, "allocating guest memory code\n");
    struct kvm_userspace_memory_region guest_region = {
        .slot = slot_id++,
        .guest_phys_addr = start,
        .memory_size = size,
        .userspace_addr = (uint64_t)memory,
    };
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &guest_region);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");
    return ret;
}

int create_bootstrap()
{
    struct kvm_sregs sregs;
    size_t mmap_size;
    int ret = -1;
    /* Creating One vCPU */
    int nent = 128;
    struct kvm_cpuid2 *cpuid2 = (struct kvm_cpuid2 *)malloc(sizeof(struct kvm_cpuid2) + nent * sizeof(struct kvm_cpuid_entry2));
    cpuid2->nent = nent;
    if (ioctl(kvmfd, KVM_GET_SUPPORTED_CPUID, cpuid2) < 0)
        err(1, "cant get cpuid");

    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);

    if (vcpufd == -1)
        err(1, "Cannot create vcpu\n");

    if (ioctl(vcpufd, KVM_SET_CPUID2, cpuid2) < 0)
        err(1, "cannot set cpuid things\n");

    /* Map the shared kvm_run structure and following data. */
    ret = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret == -1)
        err(1, "KVM_GET_VCPU_MMAP_SIZE");
    mmap_size = ret;
    if (mmap_size < sizeof(*run))
        errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
    run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
    if (!run)
        err(1, "mmap vcpu");

    /* Initializing vCPU Registers */
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

int launch_vm(uint64_t boot_rip, uint64_t app_rip, uint64_t sp)
{

    int ret;
    /* Updating vCPU Registers */
    struct kvm_regs regs = {
        .rip = boot_rip, /* Setting The RIP Register To The Bootstrap Entry Point */
        .rflags = 0x2,
        .r15 = app_rip, /* User Application Entry Point */
        .r14 = sp, /* User Application Stack Starting Address */
    };
    ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");

    while (1)
    {
        if (ioctl(vcpufd, KVM_RUN, NULL) == -1)
            err(1, "KVM_RUN");
        else
        {
            if (vmexit_handler(run->exit_reason) == 0)
                break;
        }
    }
    return 0;
}

int vmexit_handler(int exit_reason)
{
    switch (exit_reason)
    {
    case KVM_EXIT_HLT:
        printf("KVM_EXIT_HLT\n");
        return syscall_handler(memory, vcpufd);
    case KVM_EXIT_IO:
        if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1 && run->io.port == 0x3f8 && run->io.count == 1)
        {
            printf("KVM_EXIT_IO: ");
            putchar(*(((char *)run) + run->io.data_offset));
            printf("\n");
            return 0;
        }
        else
            errx(1, "unhandled KVM_EXIT_IO %d", run->io.port == 0x3f8);
        break;
    case KVM_EXIT_FAIL_ENTRY:
        errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
             (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
    case KVM_EXIT_INTERNAL_ERROR:
        errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x", run->internal.suberror);
    case KVM_EXIT_SHUTDOWN:
        errx(1, "SHUTDOWN");
        break;
    default:
        errx(1, "exit_reason = 0x%d", exit_reason);
    }
    return 1;
}

uint8_t *get_memory()
{
    return memory;
}