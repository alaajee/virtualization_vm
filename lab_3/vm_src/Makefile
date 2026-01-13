MUSL_DIR=$(shell pwd)/musl
MANAGER_DIR=$(shell pwd)/../manager
LOADER_DIR=$(shell pwd)/../loader
SYSCALL_DIR=$(shell pwd)/../syscall_handler
LINKER_DIR=$(shell pwd)/linker
BIN=./bin
SRC=./src
NASM=nasm -f elf64
LD=ld  -m elf_x86_64
MUSL=$(realpath musl/obj/musl-gcc)
GCC=gcc -g

all: save restore boot app_img

save: musl  boot app_img
	$(GCC) ../syscall_manager/syscall_handler.c ../vm_manager/manager.c ../load_manager/loader.c ../memory_manager/memory.c src/save.c -o bin/save 
	./bin/save

restore:
	$(GCC) ../syscall_manager/syscall_handler.c ../vm_manager/manager.c ../load_manager/loader.c ../memory_manager/memory.c src/restore.c -o bin/restore 
	./bin/restore

app_img:
	$(MUSL) -static -c $(SRC)/app.c 
	$(MUSL) -static -o $(BIN)/app_img app.o -T $(LINKER_DIR)/app_linker.ld  
	rm app.o

boot:
	$(NASM) $(SRC)/boot.asm 
	$(LD) -T $(LINKER_DIR)/boot_linker.ld $(SRC)/boot.o -o $(BIN)/boot 
	rm $(SRC)/boot.o

 musl:
	mkdir -p bin
	tar -xvf musl.tar.gz &&	mv musl-1.2.4/ musl
	sed -i '/errno = -r;/d' musl/src/internal/syscall_ret.c
	cp ../utils/exit.c musl/src/exit
	cd musl && ./configure CFLAGS="-mno-default -mfpmath=387 -O0 -g" --disabled-shared  --prefix=$(MUSL_DIR)/musl_installation 
	cd musl && make -j 20   && make install 

clean:
	rm bin/*

clean-hard: 
	sudo rm -r musl
	rm bin/*

