#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pe_exports.h"

#pragma pack(push, 1)

typedef struct {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name;
    uint32_t base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t address_of_functions;
    uint32_t address_of_names;
    uint32_t address_of_name_ordinals;
} ExportDirectory;

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

    if (fseek(file, section_table_offset, SEEK_SET) != 0) {
        return 0;
    }

    for (uint16_t i = 0; i < coff->number_of_sections; i++) {

        SectionHeader section;

        if (fread(&section, sizeof(section), 1, file) != 1) {
            return 0;
        }

        uint32_t section_size = section.virtual_size;

        if (section.size_of_raw_data > section_size) {
            section_size = section.size_of_raw_data;
        }

        if (rva >= section.virtual_address &&
            rva < section.virtual_address + section_size) {

            return section.pointer_to_raw_data +
            (rva - section.virtual_address);
            }
    }

    return 0;
}


static int read_string(FILE *file,
                       uint32_t offset,
                       char *buffer,
                       size_t buffer_size)
{
    if (fseek(file, offset, SEEK_SET) != 0) {
        return 0;
    }

    size_t i = 0;

    while (i + 1 < buffer_size) {

        int c = fgetc(file);

        if (c == EOF) {
            return 0;
        }

        if (c == '\0') {
            buffer[i] = '\0';
            return 1;
        }

        buffer[i++] = (char)c;
    }

    buffer[buffer_size - 1] = '\0';

    return 1;
}


void pe_print_exports(FILE *file,
                      const COFFHeader *coff,
                      uint32_t pe_offset)
{
    printf("\n[+] Exports:\n");

    /*
     * Optional Header починається після:
     *
     * PE signature = 4 bytes
     * COFF Header = sizeof(COFFHeader)
     */

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

        memcpy(&magic,
               optional_header,
               sizeof(magic));

        uint32_t data_directory_offset;

        if (magic == 0x20B) {
            /*
             * PE32+
             */
            data_directory_offset = 0x70;
        }
        else if (magic == 0x10B) {
            /*
             * PE32
             */
            data_directory_offset = 0x60;
        }
        else {
            printf("[-] Unknown Optional Header magic: 0x%04X\n",
                   magic);

            free(optional_header);
            return;
        }

        /*
         * DataDirectory[0] = Export Directory
         *
         * +0 = RVA
         * +4 = Size
         */

        if (data_directory_offset + 8 >
            coff->size_of_optional_header) {

            printf("[-] No Export Directory\n");

        free(optional_header);
        return;
            }

            uint32_t export_rva;
            uint32_t export_size;

            memcpy(&export_rva,
                   optional_header + data_directory_offset,
                   sizeof(export_rva));

            memcpy(&export_size,
                   optional_header + data_directory_offset + 4,
                   sizeof(export_size));

            free(optional_header);

            if (export_rva == 0 || export_size == 0) {
                printf("[-] No exports\n");
                return;
            }

            printf("    Export RVA:  0x%08X\n", export_rva);
            printf("    Export Size: 0x%08X\n", export_size);

            uint32_t export_offset =
            rva_to_file_offset(file,
                               coff,
                               pe_offset,
                               export_rva);

            if (export_offset == 0) {
                printf("[-] Cannot convert Export RVA\n");
                return;
            }

            if (fseek(file, export_offset, SEEK_SET) != 0) {
                perror("fseek Export Directory");
                return;
            }

            ExportDirectory exports;

            if (fread(&exports,
                sizeof(exports),
                      1,
                      file) != 1) {

                perror("fread Export Directory");
            return;
                      }

                      printf("    DLL Name RVA:       0x%08X\n",
                             exports.name);

                      printf("    Base:               %u\n",
                             exports.base);

                      printf("    Number of Functions: %u\n",
                             exports.number_of_functions);

                      printf("    Number of Names:     %u\n",
                             exports.number_of_names);

                      /*
                       * Отримуємо назву DLL.
                       */

                      uint32_t dll_name_offset =
                      rva_to_file_offset(file,
                                         coff,
                                         pe_offset,
                                         exports.name);

                      if (dll_name_offset != 0) {

                          char dll_name[256];

                          if (read_string(file,
                              dll_name_offset,
                              dll_name,
                              sizeof(dll_name))) {

                              printf("    DLL Name:           %s\n",
                                     dll_name);
                              }
                      }

                      if (exports.number_of_names == 0) {
                          printf("\n    No named exports.\n");
                          return;
                      }

                      /*
                       * Знаходимо три таблиці:
                       *
                       * AddressOfNames
                       * AddressOfNameOrdinals
                       * AddressOfFunctions
                       */

                      uint32_t names_offset =
                      rva_to_file_offset(file,
                                         coff,
                                         pe_offset,
                                         exports.address_of_names);

                      uint32_t ordinals_offset =
                      rva_to_file_offset(file,
                                         coff,
                                         pe_offset,
                                         exports.address_of_name_ordinals);

                      uint32_t functions_offset =
                      rva_to_file_offset(file,
                                         coff,
                                         pe_offset,
                                         exports.address_of_functions);

                      if (names_offset == 0 ||
                          ordinals_offset == 0 ||
                          functions_offset == 0) {

                          printf("[-] Cannot locate export tables\n");
                      return;
                          }

                          printf("\n    Functions:\n");

                          for (uint32_t i = 0;
                               i < exports.number_of_names;
    i++) {

                              /*
                               * AddressOfNames[i]
                               */

                              uint32_t name_rva;

                              if (fseek(file,
                                  names_offset +
                                  i * sizeof(uint32_t),
                                        SEEK_SET) != 0) {
                                  continue;
                                        }

                                        if (fread(&name_rva,
                                            sizeof(name_rva),
                                                  1,
                                                  file) != 1) {
                                            continue;
                                                  }

                                                  uint32_t name_offset =
                                                  rva_to_file_offset(file,
                                                                     coff,
                                                                     pe_offset,
                                                                     name_rva);

                                                  if (name_offset == 0) {
                                                      continue;
                                                  }

                                                  char name[256];

                                                  if (!read_string(file,
                                                      name_offset,
                                                      name,
                                                      sizeof(name))) {
                                                      continue;
                                                      }

                                                      /*
                                                       * AddressOfNameOrdinals[i]
                                                       */

                                                      uint16_t ordinal_index;

                                                      if (fseek(file,
                                                          ordinals_offset +
                                                          i * sizeof(uint16_t),
                                                                SEEK_SET) != 0) {
                                                          continue;
                                                                }

                                                                if (fread(&ordinal_index,
                                                                    sizeof(ordinal_index),
                                                                          1,
                                                                          file) != 1) {
                                                                    continue;
                                                                          }

                                                                          /*
                                                                           * AddressOfFunctions[ordinal_index]
                                                                           */

                                                                          uint32_t function_rva;

                                                                          if (fseek(file,
                                                                              functions_offset +
                                                                              ordinal_index * sizeof(uint32_t),
                                                                                    SEEK_SET) != 0) {
                                                                              continue;
                                                                                    }

                                                                                    if (fread(&function_rva,
                                                                                        sizeof(function_rva),
                                                                                              1,
                                                                                              file) != 1) {
                                                                                        continue;
                                                                                              }

                                                                                              uint32_t ordinal =
                                                                                              exports.base + ordinal_index;

                                                                                              printf("      Ordinal: %-5u "
                                                                                              "RVA: 0x%08X  %s\n",
                                                                                              ordinal,
                                                                                              function_rva,
                                                                                              name);
    }
}
