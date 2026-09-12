#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <capstone/capstone.h>

#include "pe.h"
#include "pe_functions.h"
#include "pe_utils.h"
#include "calls.h"


static int is_executable_section(const SectionHeader *section)
{
    return (section->characteristics & 0x20000000u) != 0;
}


static int is_executable_rva(const SectionHeader *sections,
                             uint16_t section_count,
                             uint64_t rva)
{
    for (uint16_t i = 0;
         i < section_count;
         i++) {

        uint32_t start =
            sections[i].virtual_address;

        uint32_t size =
            sections[i].virtual_size;

        if (sections[i].size_of_raw_data > size)
            size = sections[i].size_of_raw_data;

        uint64_t end =
            (uint64_t)start + size;

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

    FunctionTable functions;

    if (!pe_load_functions(file,
                           coff,
                           pe_offset,
                           &functions)) {

        fprintf(stderr,
                "Error: failed to load .pdata functions\n");

        cs_close(&handle);
        return;
    }

    long section_offset =
        (long)pe_offset +
        4L +
        (long)sizeof(COFFHeader) +
        (long)coff->size_of_optional_header;

    if (fseek(file, section_offset, SEEK_SET) != 0) {

        fprintf(stderr,
                "Error: failed to seek to section headers\n");

        pe_free_functions(&functions);
        cs_close(&handle);
        return;
    }

    SectionHeader *sections =
        calloc(coff->number_of_sections,
               sizeof(SectionHeader));

    if (!sections) {

        fprintf(stderr,
                "Error: failed to allocate section table\n");

        pe_free_functions(&functions);
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
        pe_free_functions(&functions);
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

    for (size_t function_index = 0;
         function_index < functions.count;
         function_index++) {

        RuntimeFunction *function =
            &functions.items[function_index];

        uint32_t begin =
            function->begin_address;

        uint32_t end =
            function->end_address;

        uint32_t size =
            end - begin;

        if (size == 0)
            continue;

        if (!is_executable_rva(sections,
                               coff->number_of_sections,
                               begin)) {
            continue;
        }

        uint32_t file_offset =
            pe_rva_to_file_offset(file,
                                  coff,
                                  pe_offset,
                                  begin);

        if (file_offset == 0)
            continue;

        uint32_t end_offset =
            pe_rva_to_file_offset(file,
                                  coff,
                                  pe_offset,
                                  end - 1);

        if (end_offset == 0)
            continue;

        size_t bytes_available =
            (size_t)(end_offset - file_offset) + 1;

        if (bytes_available < size)
            size = (uint32_t)bytes_available;

        uint8_t *buffer =
            malloc(size);

        if (!buffer)
            continue;

        if (fseek(file, file_offset, SEEK_SET) != 0) {
            free(buffer);
            continue;
        }

        if (fread(buffer,
                  1,
                  size,
                  file) != size) {

            free(buffer);
            continue;
        }

        cs_insn *insn = NULL;

        size_t count =
            cs_disasm(handle,
                      buffer,
                      size,
                      begin,
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
             * Direct CALL rel32:
             *
             * E8 xx xx xx xx
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

                    printf("    Function %zu  "
                           "0x%08X-0x%08X\n",
                           function_index,
                           begin,
                           end);

                    printf("      0x%08llX  CALL -> "
                           "0x%08llX  [direct] [%s]\n",
                           (unsigned long long)insn[j].address,
                           (unsigned long long)target,
                           valid_target ? "exec" : "invalid");

                    displayed_calls++;
                }
            }
            else {

                indirect_calls++;

                if (should_display) {

                    printf("    Function %zu  "
                           "0x%08X-0x%08X\n",
                           function_index,
                           begin,
                           end);

                    printf("      0x%08llX  CALL -> %s  "
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

    printf("\n    [+] Functions analyzed:     %zu\n",
           functions.count);

    printf("    [+] Total CALL instructions: %zu\n",
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

    free(sections);
    pe_free_functions(&functions);
    cs_close(&handle);
}
