#include <stdio.h>
#include "pe_sections.h"

void pe_print_sections(FILE *file, const COFFHeader *coff)
{
    printf("\n[+] Sections:\n");

    for (uint16_t i = 0; i < coff->number_of_sections; i++) {

        SectionHeader section;

        if (fread(&section, sizeof(section), 1, file) != 1) {
            perror("fread Section Header");
            return;
        }

        char name[9];

        for (int j = 0; j < 8; j++) {
            name[j] = section.name[j];
        }

        name[8] = '\0';

        printf("  [%2u] %-8s\n", i, name);

        printf("       Virtual Address: 0x%08X\n",
               section.virtual_address);

        printf("       Virtual Size:    0x%08X\n",
               section.virtual_size);

        printf("       Raw Offset:      0x%08X\n",
               section.pointer_to_raw_data);

        printf("       Raw Size:        0x%08X\n",
               section.size_of_raw_data);

        printf("       Characteristics: 0x%08X\n",
               section.characteristics);
    }
}
