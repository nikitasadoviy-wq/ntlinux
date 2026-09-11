#include <stdio.h>
#include <stdint.h>

#include "pe_utils.h"

uint32_t pe_rva_to_file_offset(FILE *file,
                               const COFFHeader *coff,
                               uint32_t pe_offset,
                               uint32_t rva)
{
    long section_offset =
    (long)pe_offset +
    4 +
    sizeof(COFFHeader) +
    coff->size_of_optional_header;

    if (fseek(file, section_offset, SEEK_SET) != 0)
        return 0;

    for (uint16_t i = 0; i < coff->number_of_sections; i++) {

        SectionHeader section;

        if (fread(&section, sizeof(section), 1, file) != 1)
            return 0;

        uint32_t section_start = section.virtual_address;
        uint32_t section_size = section.virtual_size;

        if (section.size_of_raw_data > section_size)
            section_size = section.size_of_raw_data;

        uint32_t section_end =
        section_start + section_size;

        if (rva >= section_start && rva < section_end) {

            uint32_t offset =
            rva - section_start;

            if (offset >= section.size_of_raw_data)
                return 0;

            return section.pointer_to_raw_data + offset;
        }
    }

    return 0;
}
