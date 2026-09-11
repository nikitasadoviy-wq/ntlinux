#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "pe_driver.h"

void pe_print_driver_profile(FILE *file,
                             const COFFHeader *coff,
                             uint32_t pe_offset)
{
    printf("\n[+] NT Driver Profile:\n");

    printf("    Architecture: ");

    if (coff->machine == 0x8664)
        printf("AMD64\n");
    else if (coff->machine == 0x014C)
        printf("x86\n");
    else if (coff->machine == 0xAA64)
        printf("ARM64\n");
    else
        printf("Unknown (0x%04X)\n", coff->machine);

    printf("    PE format:    ");

    long optional_offset =
    (long)pe_offset +
    4 +
    sizeof(COFFHeader);

    if (fseek(file, optional_offset, SEEK_SET) != 0) {
        printf("Unknown\n");
        return;
    }

    uint16_t magic;

    if (fread(&magic, sizeof(magic), 1, file) != 1) {
        printf("Unknown\n");
        return;
    }

    if (magic == 0x20B)
        printf("PE32+\n");
    else if (magic == 0x10B)
        printf("PE32\n");
    else
        printf("Unknown (0x%04X)\n", magic);

    printf("    Sections:     %u\n",
           coff->number_of_sections);

    /*
     * EntryPoint знаходиться після:
     *
     * Magic      2 bytes
     * Linker     2 bytes
     * SizeCode   4 bytes
     *
     * Тобто AddressOfEntryPoint має offset 0x10
     * від початку Optional Header.
     */

    if (fseek(file,
        optional_offset + 0x10,
        SEEK_SET) != 0) {
        return;
        }

        uint32_t entry_point;

    if (fread(&entry_point,
        sizeof(entry_point),
              1,
              file) != 1) {
        return;
              }

              printf("    EntryPoint:   0x%08X\n",
                     entry_point);

              /*
               * Поки що визначаємо базову ознаку
               * kernel-mode Windows driver:
               *
               * імпорт ntoskrnl.exe буде перевірятися
               * окремим import API у наступній версії.
               */

              printf("\n    Characteristics:\n");

              printf("      [x] PE executable\n");

              if (coff->machine == 0x8664 ||
                  coff->machine == 0x014C ||
                  coff->machine == 0xAA64) {

                  printf("      [x] Supported CPU architecture\n");
                  }

}
