#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <capstone/capstone.h>

#include "calls.h"

#define IMAGE_SCN_MEM_EXECUTE 0x20000000

void pe_find_calls(FILE *file,
                   const COFFHeader *coff,
                   uint32_t pe_offset)
{
    if (coff->machine != 0x8664) {
        printf("\n[-] CALL analysis skipped: unsupported architecture\n");
        return;
    }

    printf("\n[+] CALL Analysis:\n");

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

    size_t total_calls = 0;
    size_t direct_calls = 0;
    size_t indirect_calls = 0;

    for (uint16_t i = 0; i < coff->number_of_sections; i++) {

        SectionHeader section;

        if (fread(&section,
            sizeof(section),
                  1,
                  file) != 1) {

            printf("[-] Failed to read section header\n");
        break;
                  }

                  if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE))
                      continue;

        if (section.size_of_raw_data == 0)
            continue;

        char name[9];

        for (int j = 0; j < 8; j++)
            name[j] = section.name[j];

        name[8] = '\0';

        printf("\n    Section: %s\n", name);

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

                cs_insn *insn = NULL;

                size_t count =
                cs_disasm(handle,
                          buffer,
                          section.size_of_raw_data,
                          section.virtual_address,
                          0,
                          &insn);

                for (size_t j = 0; j < count; j++) {

                    /*
                     * Direct CALL:
                     *
                     *   E8 xx xx xx xx
                     *
                     * Capstone gives the resolved target
                     * in op_str, but we calculate it ourselves
                     * from the instruction bytes.
                     */
                    if (insn[j].id == X86_INS_CALL) {

                        total_calls++;

                        if (insn[j].size >= 5 &&
                            insn[j].bytes[0] == 0xE8) {

                            int32_t displacement =
                            (int32_t)(
                                (uint32_t)insn[j].bytes[1] |
                                ((uint32_t)insn[j].bytes[2] << 8) |
                                ((uint32_t)insn[j].bytes[3] << 16) |
                                ((uint32_t)insn[j].bytes[4] << 24)
                            );

                        uint64_t target =
                        insn[j].address +
                        insn[j].size +
                        displacement;

                        printf("    0x%08llX  CALL  -> 0x%08llX  [direct]\n",
                               (unsigned long long)insn[j].address,
                               (unsigned long long)target);

                        direct_calls++;

                            } else {

                                /*
                                 * CALL through register or memory.
                                 *
                                 * We don't try to resolve it yet.
                                 */
                                printf("    0x%08llX  CALL  -> %-25s [indirect]\n",
                                       (unsigned long long)insn[j].address,
                                       insn[j].op_str);

                                indirect_calls++;
                            }
                    }
                }

                cs_free(insn, count);
                free(buffer);
    }

    printf("\n    [+] Total CALL instructions: %zu\n",
           total_calls);

    printf("    [+] Direct CALLs:            %zu\n",
           direct_calls);

    printf("    [+] Indirect CALLs:          %zu\n",
           indirect_calls);

    cs_close(&handle);
}
