#include "manager.h"

int kvmfd, vmfd, vcpufd;
struct kvm_run *run;

struct kvm_image_format {
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    size_t size_memory;
    uint8_t *memory;

	__u64 msr_lstar;           // LSTAR (0xC0000082) - syscall handler address
    __u64 msr_star;            // STAR (0xC0000081) - segment selectors
    __u64 msr_sfmask;          // SFMASK (0xC0000084) - RFLAGS mask
    __u64 msr_efer;
}kvm_image_format;

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
    
    free(cpuid2);
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
        printf("KVM_EXIT_SHUTDOWN - VM halted\n");
        return 0;
    default:
        errx(1, "exit_reason = 0x%x", exit_reason);
    }
    return 1;
}

uint8_t *get_memory()
{
    return memory;
}

void dump_vcpu_registers()
{
    if (ioctl(vcpufd, KVM_GET_REGS, &kvm_image_format.regs) == -1)
        err(1, "KVM_GET_REGS in dump");
    if (ioctl(vcpufd, KVM_GET_SREGS, &kvm_image_format.sregs) == -1)
        err(1, "KVM_GET_SREGS in dump");
}

void dump_memory()
{
    kvm_image_format.memory = get_memory();
    kvm_image_format.size_memory = 0xF000;
}

void dump_msrs()
{
    struct {
        struct kvm_msrs info;
        struct kvm_msr_entry entries[3];
    } msr_data = {
        .info.nmsrs = 3,
    };

    msr_data.entries[0].index = 0xC0000082;  // LSTAR
    msr_data.entries[1].index = 0xC0000081;  // STAR
    msr_data.entries[2].index = 0xC0000080;  // EFER
    
    if (ioctl(vcpufd, KVM_GET_MSRS, &msr_data) == -1) {
        err(1, "KVM_GET_MSRS in dump");
    }
    
    kvm_image_format.msr_lstar = msr_data.entries[0].data;
    kvm_image_format.msr_star = msr_data.entries[1].data;
    kvm_image_format.msr_efer = msr_data.entries[2].data;
}


int dump()
{
    // Capture current vCPU state (RIP already advanced by syscall_handler)
    dump_vcpu_registers();
    dump_memory();
    dump_msrs();
    FILE *fd = fopen("kvm_image_dump.bin", "wb");
    if (fd == NULL) {
        perror("Error opening dump file");
        return 0;
    }

    // Write each field separately (DO NOT write the pointer!)
    if (fwrite(&kvm_image_format.regs, sizeof(struct kvm_regs), 1, fd) != 1) {
        perror("Failed to write regs");
        fclose(fd);
        return 0;
    }
    
    if (fwrite(&kvm_image_format.sregs, sizeof(struct kvm_sregs), 1, fd) != 1) {
        perror("Failed to write sregs");
        fclose(fd);
        return 0;
    }
    
    if (fwrite(&kvm_image_format.size_memory, sizeof(size_t), 1, fd) != 1) {
        perror("Failed to write size_memory");
        fclose(fd);
        return 0;
    }
    
    // Write the actual memory content (not the pointer value!)
    if (fwrite(kvm_image_format.memory, kvm_image_format.size_memory, 1, fd) != 1) {
        perror("Failed to write memory");
        fclose(fd);
        return 0;
    }
    
    // WRITE (not READ!) the MSRs
    if (fwrite(&kvm_image_format.msr_lstar, sizeof(__u64), 1, fd) != 1) {
        perror("Failed to write msr_lstar");
        fclose(fd);
        return 0;
    }

    if (fwrite(&kvm_image_format.msr_star, sizeof(__u64), 1, fd) != 1) {
        perror("Failed to write msr_star");
        fclose(fd);
        return 0;
    }

    if (fwrite(&kvm_image_format.msr_sfmask, sizeof(__u64), 1, fd) != 1) {
        perror("Failed to write msr_sfmask");
        fclose(fd);
        return 0;
    }

    if (fwrite(&kvm_image_format.msr_efer, sizeof(__u64), 1, fd) != 1) {
        perror("Failed to write msr_efer");
        fclose(fd);
        return 0;
    }
    
    fclose(fd);
       
    // Exit the VMM after SAVE operation
    exit(0);
    
    return 1;
}


int restore(){
    FILE *fd;
    fd = fopen("kvm_image_dump.bin", "rb");
    if (!fd) {
        perror("fopen kvm_image_dump.bin");
        return -1;
    }
    
    // Read each field separately - DO NOT read the whole structure!
    if (fread(&kvm_image_format.regs, sizeof(struct kvm_regs), 1, fd) != 1) {
        perror("fread regs");
        fclose(fd);
        return -1;
    }

    if (fread(&kvm_image_format.sregs, sizeof(struct kvm_sregs), 1, fd) != 1) {
        perror("fread sregs");
        fclose(fd);
        return -1;
    }

    if (fread(&kvm_image_format.size_memory, sizeof(size_t), 1, fd) != 1) {
        perror("fread size_memory");
        fclose(fd);
        return -1;
    }


   
    size_t bytes_read = fread(get_memory(), 1, kvm_image_format.size_memory, fd);
    if (bytes_read != kvm_image_format.size_memory) {
        fprintf(stderr, "Error reading memory: expected %lu bytes, got %zu bytes\n",
                kvm_image_format.size_memory, bytes_read);
        fclose(fd);
        return -1;
    }

    // NOW read MSRs (AFTER memory!)
    if (fread(&kvm_image_format.msr_lstar, sizeof(__u64), 1, fd) != 1) {
        perror("fread msr_lstar");
        fclose(fd);
        return -1;
    }

    if (fread(&kvm_image_format.msr_star, sizeof(__u64), 1, fd) != 1) {
        perror("fread msr_star");
        fclose(fd);
        return -1;
    }

    if (fread(&kvm_image_format.msr_sfmask, sizeof(__u64), 1, fd) != 1) {
        perror("fread msr_sfmask");
        fclose(fd);
        return -1;
    }

    if (fread(&kvm_image_format.msr_efer, sizeof(__u64), 1, fd) != 1) {
        perror("fread msr_efer");
        fclose(fd);
        return -1;
    }

    fclose(fd);

    if (ioctl(vcpufd, KVM_SET_SREGS, &kvm_image_format.sregs) == -1) {
        perror("KVM_SET_SREGS");
        return -1;
    }

    
    if (ioctl(vcpufd, KVM_SET_REGS, &kvm_image_format.regs) == -1) {
        perror("KVM_SET_REGS");
        return -1;
    }
 

    /* 7. Restore MSRs */
    struct {
        struct kvm_msrs info;
        struct kvm_msr_entry entries[4];
    } msr_data = {
        .info.nmsrs = 4
    };

    // LSTAR - syscall handler address
    msr_data.entries[0].index = 0xC0000082;
    msr_data.entries[0].data = kvm_image_format.msr_lstar;

    // STAR - code segments
    msr_data.entries[1].index = 0xC0000081;
    msr_data.entries[1].data = kvm_image_format.msr_star;


    // EFER
    msr_data.entries[2].index = 0xC0000080;
    msr_data.entries[2].data = kvm_image_format.msr_efer;

    if (ioctl(vcpufd, KVM_SET_MSRS, &msr_data) == -1) {
        perror("KVM_SET_MSRS");
        return -1;
    }

    /* 6. Resume VM execution */
    while (1) {
        if (ioctl(vcpufd, KVM_RUN, NULL) == -1) {
            perror("KVM_RUN");
            return -1;
        }
        
        if (vmexit_handler(run->exit_reason) == 0)
            break;
    }
    return 0;
}