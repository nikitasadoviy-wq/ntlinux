#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <capstone/capstone.h>

#include "disasm_x64.h"

#define IMAGE_SCN_MEM_EXECUTE 0x20000000

void pe_disasm_x64(FILE *file,
                   const COFFHeader *coff,
                   uint32_t pe_offset)
{
    if (coff->machine != 0x8664) {
        printf("\n[-] x86-64 disassembly skipped: unsupported architecture\n");
        return;
    }

    printf("\n[+] x86-64 Disassembly:\n");

    csh handle;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("[-] Failed to initialize Capstone\n");
        return;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

    long section_table_offset =
    (long)pe_offset +
    4 +
    sizeof(COFFHeader) +
    coff->size_of_optional_header;

    if (fseek(file, section_table_offset, SEEK_SET) != 0) {
        printf("[-] Failed to seek to section table\n");
        cs_close(&handle);
        return;
    }

    for (uint16_t i = 0; i < coff->number_of_sections; i++) {

        SectionHeader section;

        if (fread(&section,
            sizeof(section),
                  1,
                  file) != 1) {

            printf("[-] Failed to read section header\n");
        break;
                  }

                  /*
                   * Only disassemble executable sections.
                   */
                  if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE))
                      continue;

        if (section.size_of_raw_data == 0)
            continue;

        char name[9];

        for (int j = 0; j < 8; j++)
            name[j] = section.name[j];

        name[8] = '\0';

        printf("\n    Section: %s\n", name);
        printf("    RVA:     0x%08X\n",
               section.virtual_address);
        printf("    Raw size: 0x%08X\n",
               section.size_of_raw_data);

        if (fseek(file,
            section.pointer_to_raw_data,
            SEEK_SET) != 0) {

            printf("    [-] Failed to seek to section data\n");
        continue;
            }

            uint8_t *buffer =
            malloc(section.size_of_raw_data);

            if (!buffer) {
                printf("    [-] Failed to allocate section buffer\n");
                continue;
            }

            if (fread(buffer,
                1,
                section.size_of_raw_data,
                file) != section.size_of_raw_data) {

                printf("    [-] Failed to read section data\n");

            free(buffer);
            continue;
                }

                cs_insn *insn;

                size_t count =
                cs_disasm(handle,
                          buffer,
                          section.size_of_raw_data,
                          section.virtual_address,
                          0,
                          &insn);

                printf("    Instructions decoded: %zu\n", count);

                size_t limit = count;

                if (limit > 100)
                    limit = 100;

        for (size_t j = 0; j < limit; j++) {

            printf("    0x%08llX  %-8s %s\n",
                   (unsigned long long)insn[j].address,
                   insn[j].mnemonic,
                   insn[j].op_str);
        }

        if (count > limit) {
            printf("    ... %zu more instructions\n",
                   count - limit);
        }

        cs_free(insn, count);
        free(buffer);
    }

    cs_close(&handle);
}
