#include "loader.h"
#include "../memory_manager/memory.h"
#include <stdlib.h>
#include <string.h>

int get_content(FILE *fd, void *dst, int offset, int size)
{

    fseek(fd, offset, SEEK_SET);
    fread(dst, 1, size, fd);

    return 0;
}

int get_hdr(FILE *fd, Elf64_Ehdr *hdr)
{
    fseek(fd, 0, SEEK_SET);
    fread(hdr, sizeof(Elf64_Ehdr), 1, fd);

    return 0;
}

FILE *get_file(char *pathname)
{
    Elf64_Ehdr hdr;
    char check[] = {0x7f, 'E', 'L', 'F'};
    FILE *fd = fopen(pathname, "rw");
    FILE *ret = NULL;
    if (fd == NULL)
    {
        printf("error while opening %s\n", pathname);
        goto out;
    }

    get_hdr(fd, &hdr);

    if (memcmp(&hdr.e_ident, check, 4))
        goto out;
    ret = fd;
out:
    return ret;
}

int page_dico[0x1000] = {0};
int load_file(char *name)
{
    FILE *fd = get_file(name);
    uint8_t *memory = get_memory();
    Elf64_Ehdr hdr;
    Elf64_Shdr *shdrs;
    uint8_t *section;
    uint32_t size, addr, offset;
    int new_page = 0;
    get_hdr(fd, &hdr);
    shdrs = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * hdr.e_shnum);
    get_content(fd, shdrs, hdr.e_shoff, hdr.e_shnum * sizeof(Elf64_Shdr));
    for (int i = 0; i < hdr.e_shnum; i++)
    {
        /* Check if section occupies memory during execution */
        if (!(shdrs[i].sh_flags & 0x2) || shdrs[i].sh_addr == 0)
            continue;
        // printf("section %lx type %x\n", shdrs[i].sh_addr, shdrs[i].sh_type);
        if (page_dico[shdrs[i].sh_addr >> 12] == 0)
        {
            page_dico[shdrs[i].sh_addr >> 12] = 1;
            new_page = shdrs[i].sh_addr & ~0xFFF;
            invalidate_page(new_page >> 12);
            memory_map(memory, shdrs[i].sh_addr, shdrs[i].sh_addr);
            // new_page = allocate_page();
            new_page = shdrs[i].sh_addr & ~0xFFF;
            invalidate_page(new_page >> 12);
            memory_map(memory, shdrs[i].sh_addr, new_page);
        }
        size = shdrs[i].sh_size;
        addr = new_page | (shdrs[i].sh_addr & 0xFFF);
        offset = shdrs[i].sh_offset;
        section = (uint8_t *)malloc(size);
        memset(section, 0, size);
        /* check if section has data (bss) */
        if (!(shdrs[i].sh_type & 0x8))
            get_content(fd, section, offset, size);
        memcpy(&memory[addr], section, size);
        free(section);
    }

    return hdr.e_entry;
}
