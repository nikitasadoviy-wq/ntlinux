#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <capstone/capstone.h>

#include "pe.h"
#include "calls.h"


static int is_executable_section(const SectionHeader *section)
{
    return (section->characteristics & 0x20000000u) != 0;
}


static int is_executable_rva(const SectionHeader *sections,
                             uint16_t section_count,
                             uint64_t rva)
{
    for (uint16_t i = 0; i < section_count; i++) {

        uint32_t start = sections[i].virtual_address;
        uint32_t size = sections[i].virtual_size;

        if (sections[i].size_of_raw_data > size)
            size = sections[i].size_of_raw_data;

        uint64_t end = (uint64_t)start + size;

        if (rva >= start && rva < end)
            return is_executable_section(&sections[i]);
    }

    return 0;
}


void pe_find_calls(FILE *file,
                   const COFFHeader *coff,
                   uint32_t pe_offset,
                   size_t limit)
{
    csh handle;

    if (cs_open(CS_ARCH_X86,
                CS_MODE_64,
                &handle) != CS_ERR_OK) {

        fprintf(stderr,
                "Error: failed to initialize Capstone\n");
        return;
    }

    cs_option(handle,
              CS_OPT_DETAIL,
              CS_OPT_OFF);

    long section_offset =
        (long)pe_offset +
        4L +
        (long)sizeof(COFFHeader) +
        (long)coff->size_of_optional_header;

    if (fseek(file, section_offset, SEEK_SET) != 0) {
        fprintf(stderr,
                "Error: failed to seek to section headers\n");
        cs_close(&handle);
        return;
    }

    SectionHeader *sections =
        calloc(coff->number_of_sections,
               sizeof(SectionHeader));

    if (!sections) {
        fprintf(stderr,
                "Error: failed to allocate section table\n");
        cs_close(&handle);
        return;
    }

    if (fread(sections,
              sizeof(SectionHeader),
              coff->number_of_sections,
              file) != coff->number_of_sections) {

        fprintf(stderr,
                "Error: failed to read section headers\n");

        free(sections);
        cs_close(&handle);
        return;
    }

    size_t total_calls = 0;
    size_t direct_calls = 0;
    size_t indirect_calls = 0;
    size_t valid_direct_calls = 0;
    size_t invalid_direct_calls = 0;
    size_t displayed_calls = 0;

    printf("\n[+] CALL Analysis:\n");

    for (uint16_t section_index = 0;
         section_index < coff->number_of_sections;
         section_index++) {

        SectionHeader *section =
            &sections[section_index];

        if (!is_executable_section(section))
            continue;

        if (section->size_of_raw_data == 0)
            continue;

        uint8_t *buffer =
            malloc(section->size_of_raw_data);

        if (!buffer) {
            fprintf(stderr,
                    "Error: failed to allocate section buffer\n");
            continue;
        }

        if (fseek(file,
                  section->pointer_to_raw_data,
                  SEEK_SET) != 0) {

            fprintf(stderr,
                    "Error: failed to seek to section data\n");

            free(buffer);
            continue;
        }

        if (fread(buffer,
                  1,
                  section->size_of_raw_data,
                  file) != section->size_of_raw_data) {

            fprintf(stderr,
                    "Error: failed to read section data\n");

            free(buffer);
            continue;
        }

        cs_insn *insn = NULL;

        size_t count =
            cs_disasm(handle,
                      buffer,
                      section->size_of_raw_data,
                      section->virtual_address,
                      0,
                      &insn);

        if (count == 0) {
            free(buffer);
            continue;
        }

        for (size_t j = 0;
             j < count;
             j++) {

            if (insn[j].id != X86_INS_CALL)
                continue;

            total_calls++;

            int should_display =
                (limit == 0 ||
                 displayed_calls < limit);

            /*
             * Direct CALL:
             *
             * E8 rel32
             */
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

                int valid_target =
                    is_executable_rva(sections,
                                       coff->number_of_sections,
                                       target);

                direct_calls++;

                if (valid_target)
                    valid_direct_calls++;
                else
                    invalid_direct_calls++;

                if (should_display) {

                    printf("    0x%08llX  CALL  -> 0x%08llX  "
                           "[direct] [%s]\n",
                           (unsigned long long)insn[j].address,
                           (unsigned long long)target,
                           valid_target ? "exec" : "invalid");

                    displayed_calls++;
                }
            }

            /*
             * All other CALL forms are currently treated
             * as indirect.
             */
            else {

                indirect_calls++;

                if (should_display) {

                    printf("    0x%08llX  CALL  -> %s  "
                           "[indirect]\n",
                           (unsigned long long)insn[j].address,
                           insn[j].op_str);

                    displayed_calls++;
                }
            }
        }

        cs_free(insn, count);
        free(buffer);
    }

    free(sections);
    cs_close(&handle);

    printf("\n    [+] Total CALL instructions: %zu\n",
           total_calls);

    printf("    [+] Direct CALLs:            %zu\n",
           direct_calls);

    printf("    [+] Indirect CALLs:          %zu\n",
           indirect_calls);

    printf("    [+] Valid direct targets:    %zu\n",
           valid_direct_calls);

    printf("    [+] Invalid direct targets:  %zu\n",
           invalid_direct_calls);

    printf("    [+] Displayed CALLs:         %zu / %zu\n",
           displayed_calls,
           total_calls);
}
