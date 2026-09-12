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
} RawRuntimeFunction;

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


int pe_load_functions(FILE *file,
                      const COFFHeader *coff,
                      uint32_t pe_offset,
                      FunctionTable *table)
{
    if (!table)
        return 0;

    table->items = NULL;
    table->count = 0;

    long section_offset =
        (long)pe_offset +
        4L +
        (long)sizeof(COFFHeader) +
        (long)coff->size_of_optional_header;

    if (fseek(file, section_offset, SEEK_SET) != 0)
        return 0;

    SectionHeader pdata;
    int found = 0;

    for (uint16_t i = 0;
         i < coff->number_of_sections;
         i++) {

        SectionHeader section;

        if (fread(&section,
                  sizeof(section),
                  1,
                  file) != 1) {
            return 0;
        }

        if (is_pdata_name(section.name)) {
            pdata = section;
            found = 1;
            break;
        }
    }

    if (!found)
        return 0;

    uint32_t record_count =
        pdata.virtual_size / sizeof(RawRuntimeFunction);

    if (record_count == 0)
        return 0;

    uint32_t pdata_offset =
        pe_rva_to_file_offset(file,
                              coff,
                              pe_offset,
                              pdata.virtual_address);

    if (pdata_offset == 0)
        return 0;

    if (fseek(file, pdata_offset, SEEK_SET) != 0)
        return 0;

    RuntimeFunction *items =
        calloc(record_count,
               sizeof(RuntimeFunction));

    if (!items)
        return 0;

    size_t valid_count = 0;

    for (uint32_t i = 0;
         i < record_count;
         i++) {

        RawRuntimeFunction raw;

        if (fread(&raw,
                  sizeof(raw),
                  1,
                  file) != 1) {
            break;
        }

        if (raw.begin_address == 0 &&
            raw.end_address == 0) {
            continue;
        }

        if (raw.begin_address >= raw.end_address)
            continue;

        items[valid_count].begin_address =
            raw.begin_address;

        items[valid_count].end_address =
            raw.end_address;

        items[valid_count].unwind_info =
            raw.unwind_info;

        valid_count++;
    }

    if (valid_count == 0) {
        free(items);
        return 0;
    }

    RuntimeFunction *shrunk =
        realloc(items,
                valid_count * sizeof(RuntimeFunction));

    if (shrunk)
        items = shrunk;

    table->items = items;
    table->count = valid_count;

    return 1;
}


void pe_free_functions(FunctionTable *table)
{
    if (!table)
        return;

    free(table->items);

    table->items = NULL;
    table->count = 0;
}


void pe_print_functions(const FunctionTable *table)
{
    if (!table || !table->items) {
        printf("\n[+] Functions:\n");
        printf("    [-] No runtime functions found\n");
        return;
    }

    printf("\n[+] Functions:\n");
    printf("    Valid functions: %zu\n",
           table->count);

    size_t display_count = table->count;

    if (display_count > 50)
        display_count = 50;

    for (size_t i = 0;
         i < display_count;
         i++) {

        const RuntimeFunction *function =
            &table->items[i];

        printf("    [%4zu]  0x%08X - 0x%08X  "
               "Unwind: 0x%08X  Size: 0x%X\n",
               i,
               function->begin_address,
               function->end_address,
               function->unwind_info,
               function->end_address -
               function->begin_address);
    }

    if (table->count > display_count) {
        printf("    ... %zu more functions omitted\n",
               table->count - display_count);
    }
}
