# ScratchVM: Lab 1

The objective of this first lab is to be able to run a binary code inside a micro virtual machine by completing the function called in the [main.c](vm_src/src/main.c) file.
Our virtual machine contains 1 vCPU and low amount of physical memory. We do not consider devices (disk, network, peripherals, ...).


## Step 0: Taking control of KVM 
* Browse the [KVM API documentation](https://www.kernel.org/doc/Documentation/virt/kvm/api.txt)
* Identify the needed ioctls for:
    * creating a virtual machine and virtual CPU,
    * accessing the virtual CPU registers,
    * allocating guest physical memory,
    * and running the VM.

## Step 1: Creating a simple virtual machine
- Create th KVM virtal machine -- create_vm() in [manager.c:12](vm_manager/manager.c)
- Create 1 virtual CPU -- create_bootstrap() in [manager.c:29](vm_manager/manager.c)

## Step 2: Loading the binary code
- Allocate guest physical memory -- create_guest_physical_memory(size) in [manager.c:23](vm_manager/manager.c)
- Copy the code in the guest physical memory area -- load_vm_code(code) in [loader.c:6](load_manager/loader.c)

## Step 3: Running the virtual machine
- Update the vCPU registers -- launch_vm() in [manager:81-83](vm_manager/manager.c)
- Run the vCPU

## Step 4: Deploying the VM
- Run the VM
```bash 
$ cd lab_1/vm_src
$ make all && make run
```
You should have this output:
```bash
6
KVM_EXIT_HLT
```
