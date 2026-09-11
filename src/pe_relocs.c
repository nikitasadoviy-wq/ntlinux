#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "pe_relocs.h"

#pragma pack(push, 1)

typedef struct {
    uint32_t virtual_address;
    uint32_t size_of_block;
} BaseRelocationBlock;

#pragma pack(pop)

static uint32_t rva_to_file_offset(FILE *file,
                                   const COFFHeader *coff,
                                   uint32_t pe_offset,
                                   uint32_t rva)
{
    long section_table_offset =
    (long)pe_offset +
    4 +
    sizeof(COFFHeader) +
    coff->size_of_optional_header;

    if (fseek(file, section_table_offset, SEEK_SET) != 0)
        return 0;

    for (uint16_t i = 0;
         i < coff->number_of_sections;
    i++) {

        SectionHeader section;

        if (fread(&section,
            sizeof(section),
                  1,
                  file) != 1)
            return 0;

        uint32_t section_size = section.virtual_size;

        if (section.size_of_raw_data > section_size)
            section_size = section.size_of_raw_data;

        if (rva >= section.virtual_address &&
            rva < section.virtual_address + section_size) {

            return section.pointer_to_raw_data +
            (rva - section.virtual_address);
            }
    }

    return 0;
}

void pe_print_relocations(FILE *file,
                          const COFFHeader *coff,
                          uint32_t pe_offset)
{
    printf("\n[+] Base Relocations:\n");

    long optional_header_offset =
    (long)pe_offset +
    4 +
    sizeof(COFFHeader);

    if (fseek(file, optional_header_offset, SEEK_SET) != 0) {
        perror("fseek Optional Header");
        return;
    }

    uint8_t *optional_header =
    malloc(coff->size_of_optional_header);

    if (!optional_header) {
        perror("malloc");
        return;
    }

    if (fread(optional_header,
        coff->size_of_optional_header,
        1,
        file) != 1) {

        perror("fread Optional Header");
    free(optional_header);
    return;
        }

        uint16_t magic;

        magic = (uint16_t)optional_header[0] |
        ((uint16_t)optional_header[1] << 8);

        uint32_t data_directory_offset;

        if (magic == 0x20B) {
            /* PE32+ */
            data_directory_offset = 0x70;
        }
        else if (magic == 0x10B) {
            /* PE32 */
            data_directory_offset = 0x60;
        }
        else {
            printf("[-] Unknown Optional Header magic: 0x%04X\n",
                   magic);

            free(optional_header);
            return;
        }

        /*
         * Data Directory #5 =
         * IMAGE_DIRECTORY_ENTRY_BASERELOC
         */

        uint32_t reloc_directory_offset =
        data_directory_offset + (5 * 8);

        if (reloc_directory_offset + 8 >
            coff->size_of_optional_header) {

            printf("[-] No Base Relocation Directory\n");

        free(optional_header);
        return;
            }

            uint32_t reloc_rva;
            uint32_t reloc_size;

            reloc_rva =
            (uint32_t)optional_header[reloc_directory_offset] |
            ((uint32_t)optional_header[reloc_directory_offset + 1] << 8) |
            ((uint32_t)optional_header[reloc_directory_offset + 2] << 16) |
            ((uint32_t)optional_header[reloc_directory_offset + 3] << 24);

            reloc_size =
            (uint32_t)optional_header[reloc_directory_offset + 4] |
            ((uint32_t)optional_header[reloc_directory_offset + 5] << 8) |
            ((uint32_t)optional_header[reloc_directory_offset + 6] << 16) |
            ((uint32_t)optional_header[reloc_directory_offset + 7] << 24);

            free(optional_header);

            if (reloc_rva == 0 || reloc_size == 0) {
                printf("[-] No relocations\n");
                return;
            }

            printf("    Relocation RVA:  0x%08X\n", reloc_rva);
            printf("    Relocation Size: 0x%08X\n", reloc_size);

            uint32_t reloc_offset =
            rva_to_file_offset(file,
                               coff,
                               pe_offset,
                               reloc_rva);

            if (reloc_offset == 0) {
                printf("[-] Cannot convert relocation RVA\n");
                return;
            }

            uint32_t processed = 0;
            uint32_t block_count = 0;
            uint32_t relocation_count = 0;

            while (processed + sizeof(BaseRelocationBlock) <= reloc_size) {

                if (fseek(file,
                    reloc_offset + processed,
                    SEEK_SET) != 0)
                    break;

                BaseRelocationBlock block;

                if (fread(&block,
                    sizeof(block),
                          1,
                          file) != 1)
                    break;

                if (block.virtual_address == 0 ||
                    block.size_of_block == 0)
                    break;

                if (block.size_of_block < sizeof(BaseRelocationBlock))
                    break;

                if (processed + block.size_of_block > reloc_size)
                    break;

                uint32_t entry_count =
                (block.size_of_block -
                sizeof(BaseRelocationBlock)) /
                sizeof(uint16_t);

                printf("\n    Block %u:\n", block_count);

                printf("      Page RVA:  0x%08X\n",
                       block.virtual_address);

                printf("      Block Size: %u\n",
                       block.size_of_block);

                printf("      Entries:    %u\n",
                       entry_count);

                for (uint32_t i = 0;
                     i < entry_count;
                i++) {

                    uint16_t entry;

                    if (fread(&entry,
                        sizeof(entry),
                              1,
                              file) != 1)
                        break;

                    uint16_t type =
                    entry >> 12;

                    uint16_t offset =
                    entry & 0x0FFF;

                    uint32_t target_rva =
                    block.virtual_address + offset;

                    printf("        [%4u] "
                    "Type: %-2u "
                    "Offset: 0x%03X "
                    "RVA: 0x%08X",
                    relocation_count,
                    type,
                    offset,
                    target_rva);

                    switch (type) {

                        case 0:
                            printf("  ABSOLUTE");
                            break;

                        case 3:
                            printf("  HIGHLOW");
                            break;

                        case 10:
                            printf("  DIR64");
                            break;

                        default:
                            printf("  UNKNOWN");
                            break;
                    }

                    printf("\n");

                    relocation_count++;
                }

                processed += block.size_of_block;
                block_count++;
            }

            printf("\n    Total Blocks:      %u\n",
                   block_count);

            printf("    Total Relocations: %u\n",
                   relocation_count);
}
