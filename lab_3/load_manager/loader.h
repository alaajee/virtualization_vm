#ifndef __LOADER__
#define __LOADER__

#include <stdio.h>
#include <stdint.h>
#include <linux/kvm.h>
#include "../memory_manager/memory.h"
#include "../vm_manager/manager.h"

#define PH_OFF  0x34
#define PH_NUM  0x2C

#define SH_OFF  0x20
#define SH_NUM  0x30   

#define PT_LOAD 0x00000001
#define SHT_SYMTAB 0x2

/* Type for a 16-bit quantity.  */
typedef unsigned short Elf32_Half;
typedef uint16_t Elf64_Half;

/* Types for signed and unsigned 32-bit quantities.  */
typedef unsigned int Elf32_Word;
typedef int Elf32_Sword;
typedef unsigned int Elf64_Word;
typedef	int  Elf64_Sword;

/* Types for signed and unsigned 64-bit quantities.  */
typedef unsigned long Elf32_Xword;
typedef long Elf32_Sxword;
typedef unsigned long Elf64_Xword;
typedef	long  Elf64_Sxword;

/* Type of addresses.  */
typedef unsigned int Elf32_Addr;
typedef unsigned long Elf64_Addr;

/* Type of file offsets.  */
typedef unsigned int Elf32_Off;
typedef unsigned long Elf64_Off;


/* Type for section indices, which are 16-bit quantities.  */
typedef unsigned short Elf32_Section;
typedef unsigned short Elf64_Section;

/* Type for version symbol information.  */
typedef Elf32_Half Elf32_Versym;
typedef Elf64_Half Elf64_Versym;


#define EI_NIDENT (16)

typedef struct
{
    unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */
    Elf32_Half e_type;                /* Object file type */
    Elf32_Half e_machine;             /* Architecture */
    Elf32_Word e_version;             /* Object file version */
    Elf32_Addr e_entry;               /* Entry point virtual address */
    Elf32_Off e_phoff;                /* Program header table file offset */
    Elf32_Off e_shoff;                /* Section header table file offset */
    Elf32_Word e_flags;               /* Processor-specific flags */
    Elf32_Half e_ehsize;              /* ELF header size in bytes */
    Elf32_Half e_phentsize;           /* Program header table entry size */
    Elf32_Half e_phnum;               /* Program header table entry count */
    Elf32_Half e_shentsize;           /* Section header table entry size */
    Elf32_Half e_shnum;               /* Section header table entry count */
    Elf32_Half e_shstrndx;            /* Section header string table index */
} Elf32_Ehdr;

typedef struct
{
    Elf32_Word p_type;   /* Segment type */
    Elf32_Off p_offset;  /* Segment file offset */
    Elf32_Addr p_vaddr;  /* Segment virtual address */
    Elf32_Addr p_paddr;  /* Segment physical address */
    Elf32_Word p_filesz; /* Segment size in file */
    Elf32_Word p_memsz;  /* Segment size in memory */
    Elf32_Word p_flags;  /* Segment flags */
    Elf32_Word p_align;  /* Segment alignment */
} Elf32_Phdr;


typedef struct
{
  Elf32_Word	sh_name;		/* Section name (string tbl index) */
  Elf32_Word	sh_type;		/* Section type */
  Elf32_Word	sh_flags;		/* Section flags */
  Elf32_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf32_Off	sh_offset;		/* Section file offset */
  Elf32_Word	sh_size;		/* Section size in bytes */
  Elf32_Word	sh_link;		/* Link to another section */
  Elf32_Word	sh_info;		/* Additional section information */
  Elf32_Word	sh_addralign;		/* Section alignment */
  Elf32_Word	sh_entsize;		/* Entry size if section holds table */
} Elf32_Shdr;


typedef struct {
	Elf32_Word	st_name;
	Elf32_Addr	st_value;
	Elf32_Word	st_size;
	unsigned char	st_info;
	unsigned char	st_other;
	Elf32_Half	st_shndx;
} Elf32_Sym;


FILE* get_file(char* path);
int load_function(FILE* file, char* name, int offset, uint32_t* memory);
int load_text_section(FILE* fd, int offset, uint32_t *memory);
int load_file(char *name);
int load_segments(FILE* fd, uint8_t* memory);
// int map(uint* memory, void* src, int size, uint32_t offset);




typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	e_phoff;		/* Program header table file offset */
  Elf64_Off	e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf64_Ehdr;

typedef struct
{
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;

typedef struct
{
  Elf64_Word	sh_name;		/* Section name (string tbl index) */
  Elf64_Word	sh_type;		/* Section type */
  Elf64_Xword	sh_flags;		/* Section flags */
  Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf64_Off	sh_offset;		/* Section file offset */
  Elf64_Xword	sh_size;		/* Section size in bytes */
  Elf64_Word	sh_link;		/* Link to another section */
  Elf64_Word	sh_info;		/* Additional section information */
  Elf64_Xword	sh_addralign;		/* Section alignment */
  Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
} Elf64_Shdr;

#endif
