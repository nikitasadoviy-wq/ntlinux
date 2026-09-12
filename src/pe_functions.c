#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pe.h"
#include "pe_functions.h"
#include "pe_utils.h"


#pragma pack(push, 1)

typedef struct {
    uint32_t begin_address;
    uint32_t end_address;
    uint32_t unwind_info;
} RuntimeFunction;

#pragma pack(pop)


static int is_pdata_name(const uint8_t name[8])
{
    return name[0] == '.' &&
           name[1] == 'p' &&
           name[2] == 'd' &&
           name[3] == 'a' &&
           name[4] == 't' &&
           name[5] == 'a';
}


void pe_print_functions(FILE *file,
                        const COFFHeader *coff,
                        uint32_t pe_offset)
{
    long section_offset =
        (long)pe_offset +
        4L +
        (long)sizeof(COFFHeader) +
        (long)coff->size_of_optional_header;

    if (fseek(file, section_offset, SEEK_SET) != 0) {
        fprintf(stderr,
                "Error: failed to seek to section headers\n");
        return;
    }

    SectionHeader pdata = {0};
    int found = 0;

    for (uint16_t i = 0;
         i < coff->number_of_sections;
         i++) {

        SectionHeader section;

        if (fread(&section,
                  sizeof(section),
                  1,
                  file) != 1) {

            fprintf(stderr,
                    "Error: failed to read section header\n");
            return;
        }

        if (is_pdata_name(section.name)) {
            pdata = section;
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("\n[+] Functions:\n");
        printf("    [-] No .pdata section found\n");
        return;
    }

    if (pdata.virtual_size < sizeof(RuntimeFunction)) {
        printf("\n[+] Functions:\n");
        printf("    [-] .pdata is too small\n");
        return;
    }

    uint32_t pdata_file_offset =
        pe_rva_to_file_offset(file,
                              coff,
                              pe_offset,
                              pdata.virtual_address);

    if (pdata_file_offset == 0) {
        printf("\n[+] Functions:\n");
        printf("    [-] Failed to convert .pdata RVA\n");
        return;
    }

    /*
     * Only parse the meaningful virtual size.
     * Do not use raw padding as function records.
     */
    uint32_t possible_records =
        pdata.virtual_size / sizeof(RuntimeFunction);

    RuntimeFunction *functions =
        calloc(possible_records,
               sizeof(RuntimeFunction));

    if (!functions) {
        fprintf(stderr,
                "Error: failed to allocate function table\n");
        return;
    }

    if (fseek(file, pdata_file_offset, SEEK_SET) != 0) {
        fprintf(stderr,
                "Error: failed to seek to .pdata\n");
        free(functions);
        return;
    }

    uint32_t valid_count = 0;

    for (uint32_t i = 0;
         i < possible_records;
         i++) {

        RuntimeFunction function;

        if (fread(&function,
                  sizeof(function),
                  1,
                  file) != 1) {
            break;
        }

        /*
         * Ignore empty records.
         */
        if (function.begin_address == 0 &&
            function.end_address == 0) {
            continue;
        }

        /*
         * A normal runtime-function entry must have
         * a non-empty address range.
         */
        if (function.begin_address >= function.end_address)
            continue;

        functions[valid_count] = function;
        valid_count++;
    }

    printf("\n[+] Functions:\n");

    printf("    .pdata RVA:       0x%08X\n",
           pdata.virtual_address);

    printf("    .pdata Virtual:   0x%08X\n",
           pdata.virtual_size);

    printf("    .pdata Raw:       0x%08X\n",
           pdata.size_of_raw_data);

    printf("    Runtime records:  %u\n",
           possible_records);

    printf("    Valid functions:  %u\n",
           valid_count);

    /*
     * Display the first 50 functions.
     */
    uint32_t display_count = valid_count;

    if (display_count > 50)
        display_count = 50;

    for (uint32_t i = 0;
         i < display_count;
         i++) {

        const RuntimeFunction *function =
            &functions[i];

        printf("    [%4u]  0x%08X - 0x%08X  "
               "Unwind: 0x%08X  Size: 0x%X\n",
               i,
               function->begin_address,
               function->end_address,
               function->unwind_info,
               function->end_address -
               function->begin_address);
    }

    if (valid_count > display_count)
        printf("    ... %u more functions omitted\n",
               valid_count - display_count);

    free(functions);
}
