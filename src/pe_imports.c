#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pe_imports.h"
#include "pe_utils.h"

#pragma pack(push, 1)

typedef struct {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name;
    uint32_t first_thunk;
} ImportDescriptor;

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


void pe_print_imports(FILE *file,
                      const COFFHeader *coff,
                      uint32_t pe_offset)
{
    printf("\n[+] Imports:\n");

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

        /*
         * PE32:
         *   DataDirectory starts at 0x60
         *
         * PE32+:
         *   DataDirectory starts at 0x70
         *
         * Import Directory = entry #1
         * Each entry = 8 bytes
         */

        if (magic == 0x20B) {
            data_directory_offset = 0x70;
        }
        else if (magic == 0x10B) {
            data_directory_offset = 0x60;
        }
        else {
            printf("[-] Unknown Optional Header magic: 0x%04X\n",
                   magic);

            free(optional_header);
            return;
        }

        uint32_t import_directory_offset =
        data_directory_offset + 8;

        if (import_directory_offset + 8 >
            coff->size_of_optional_header) {

            printf("[-] No Import Directory\n");

        free(optional_header);
        return;
            }

            uint32_t import_rva;
            uint32_t import_size;

            memcpy(&import_rva,
                   optional_header + import_directory_offset,
                   sizeof(import_rva));

            memcpy(&import_size,
                   optional_header + import_directory_offset + 4,
                   sizeof(import_size));

            free(optional_header);

            if (import_rva == 0 || import_size == 0) {
                printf("[-] No imports\n");
                return;
            }

            printf("    Import RVA:  0x%08X\n", import_rva);
            printf("    Import Size: 0x%08X\n", import_size);

            uint32_t import_offset =
            pe_rva_to_file_offset(file,
                                  coff,
                                  pe_offset,
                                  import_rva);

            if (import_offset == 0) {
                printf("[-] Cannot convert Import RVA\n");
                return;
            }

            printf("\n    DLLs:\n");

            uint32_t descriptor_offset = import_offset;

            while (1) {

                if (fseek(file, descriptor_offset, SEEK_SET) != 0) {
                    printf("[-] Cannot seek Import Descriptor\n");
                    return;
                }

                ImportDescriptor descriptor;

                if (fread(&descriptor,
                    sizeof(descriptor),
                          1,
                          file) != 1) {

                    printf("[-] Cannot read Import Descriptor\n");
                return;
                          }

                          /*
                           * Null descriptor marks the end.
                           */

                          if (descriptor.characteristics == 0 &&
                              descriptor.time_date_stamp == 0 &&
                              descriptor.forwarder_chain == 0 &&
                              descriptor.name == 0 &&
                              descriptor.first_thunk == 0) {

                              break;
                              }

                              uint32_t dll_name_offset =
                              rva_to_file_offset(file,
                                                 coff,
                                                 pe_offset,
                                                 descriptor.name);

                              if (dll_name_offset == 0) {
                                  printf("\n      <invalid DLL name>\n");
                                  descriptor_offset += sizeof(ImportDescriptor);
                                  continue;
                              }

                              char dll_name[256];

                              if (!read_string(file,
                                  dll_name_offset,
                                  dll_name,
                                  sizeof(dll_name))) {

                                  printf("\n      <invalid DLL name>\n");
                              descriptor_offset += sizeof(ImportDescriptor);
                              continue;
                                  }

                                  printf("\n      %s\n", dll_name);

                                  /*
                                   * OriginalFirstThunk / Characteristics contains
                                   * the Import Name Table RVA.
                                   *
                                   * For most normal PE files this is descriptor.characteristics.
                                   */

                                  uint32_t thunk_rva = descriptor.characteristics;

                                  if (thunk_rva == 0) {
                                      thunk_rva = descriptor.first_thunk;
                                  }

                                  uint32_t thunk_offset =
                                  rva_to_file_offset(file,
                                                     coff,
                                                     pe_offset,
                                                     thunk_rva);

                                  if (thunk_offset == 0) {
                                      printf("        [-] Cannot locate thunk table\n");

                                      descriptor_offset += sizeof(ImportDescriptor);
                                      continue;
                                  }

                                  /*
                                   * We only need the lower 32 bits for RVA conversion.
                                   * For PE32+ each thunk is 8 bytes.
                                   * For PE32 each thunk is 4 bytes.
                                   */

                                  uint32_t thunk_size =
                                  (magic == 0x20B) ? 8 : 4;

                                  uint32_t index = 0;

                                  while (1) {

                                      uint64_t thunk_value = 0;

                                      if (fseek(file,
                                          thunk_offset +
                                          index * thunk_size,
                                          SEEK_SET) != 0) {
                                          break;
                                          }

                                          if (magic == 0x20B) {

                                              if (fread(&thunk_value,
                                                  sizeof(uint64_t),
                                                        1,
                                                        file) != 1) {
                                                  break;
                                                        }

                                          } else {

                                              uint32_t value32;

                                              if (fread(&value32,
                                                  sizeof(value32),
                                                        1,
                                                        file) != 1) {
                                                  break;
                                                        }

                                                        thunk_value = value32;
                                          }

                                          /*
                                           * Zero terminates the thunk table.
                                           */

                                          if (thunk_value == 0) {
                                              break;
                                          }

                                          /*
                                           * High bit means import by ordinal.
                                           *
                                           * PE32+ -> bit 63
                                           * PE32  -> bit 31
                                           */

                                          uint64_t ordinal_flag =
                                          (magic == 0x20B)
                                          ? (1ULL << 63)
                                          : (1ULL << 31);

                                          if (thunk_value & ordinal_flag) {

                                              uint16_t ordinal =
                                              (uint16_t)(thunk_value & 0xFFFF);

                                              printf("        Ordinal: %u\n",
                                                     ordinal);

                                          } else {

                                              /*
                                               * Otherwise thunk_value is an RVA
                                               * pointing to IMAGE_IMPORT_BY_NAME.
                                               *
                                               * First 2 bytes = hint.
                                               * Following bytes = function name.
                                               */

                                              uint32_t name_rva =
                                              (uint32_t)(thunk_value & 0xFFFFFFFF);

                                              uint32_t name_offset =
                                              rva_to_file_offset(file,
                                                                 coff,
                                                                 pe_offset,
                                                                 name_rva);

                                              if (name_offset == 0) {
                                                  index++;
                                                  continue;
                                              }

                                              if (fseek(file,
                                                  name_offset + 2,
                                                  SEEK_SET) != 0) {
                                                  index++;
                                              continue;
                                                  }

                                                  char function_name[256];

                                                  size_t pos = 0;

                                                  while (pos + 1 < sizeof(function_name)) {

                                                      int c = fgetc(file);

                                                      if (c == EOF) {
                                                          break;
                                                      }

                                                      if (c == '\0') {
                                                          break;
                                                      }

                                                      function_name[pos++] =
                                                      (char)c;
                                                  }

                                                  function_name[pos] = '\0';

                                                  printf("        %s\n",
                                                         function_name);
                                          }

                                          index++;
                                  }

                                  descriptor_offset +=
                                  sizeof(ImportDescriptor);
            }
}
