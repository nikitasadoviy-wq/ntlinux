#include <stdio.h>
#include <stdint.h>

#include "pe.h"
#include "calls.h"
#include "disasm_x64.h"
#include "pe_driver.h"
#include "pe_relocs.h"
#include "pe_strings.h"
#include "pe_imports.h"
#include "pe_sections.h"
#include "pe_abi.h"
#include "pe_exports.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: %s <file.sys>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");

    if (!file) {
        perror("fopen");
        return 1;
    }

    DOSHeader dos;

    if (fread(&dos, sizeof(dos), 1, file) != 1) {
        perror("fread DOS header");
        fclose(file);
        return 1;
    }

    if (dos.e_magic != 0x5A4D) {
        printf("[-] Not a PE file\n");
        fclose(file);
        return 1;
    }

    printf("[+] DOS signature: MZ\n");

    if (fseek(file, dos.e_lfanew, SEEK_SET) != 0) {
        perror("fseek");
        fclose(file);
        return 1;
    }

    uint32_t pe_signature;

    if (fread(&pe_signature, sizeof(pe_signature), 1, file) != 1) {
        perror("fread PE signature");
        fclose(file);
        return 1;
    }

    if (pe_signature != 0x00004550) {
        printf("[-] Invalid PE signature\n");
        fclose(file);
        return 1;
    }

    printf("[+] PE signature: PE\\0\\0\n");

    COFFHeader coff;

    if (fread(&coff, sizeof(coff), 1, file) != 1) {
        perror("fread COFF header");
        fclose(file);
        return 1;
    }

    printf("[+] Machine: ");

    switch (coff.machine) {

        case 0x8664:
            printf("AMD64 (x86-64)\n");
            break;

        case 0xAA64:
            printf("ARM64\n");
            break;

        case 0x014c:
            printf("x86 (32-bit)\n");
            break;

        default:
            printf("Unknown (0x%04X)\n", coff.machine);
            break;
    }

    printf("[+] Sections: %u\n",
           coff.number_of_sections);

    printf("[+] Optional Header size: %u bytes\n",
           coff.size_of_optional_header);

    OptionalHeaderStart optional;

    if (fread(&optional, sizeof(optional), 1, file) != 1) {
        perror("fread Optional Header");
        fclose(file);
        return 1;
    }

    printf("[+] Optional Header magic: ");

    switch (optional.magic) {

        case 0x20B:
            printf("PE32+ (64-bit)\n");
            break;

        case 0x10B:
            printf("PE32 (32-bit)\n");
            break;

        default:
            printf("Unknown (0x%04X)\n",
                   optional.magic);
            break;
    }

    printf("[+] EntryPoint: 0x%08X\n",
           optional.address_of_entry_point);

    if (fseek(file,
        coff.size_of_optional_header - sizeof(optional),
              SEEK_CUR) != 0) {

        perror("fseek remaining Optional Header");
    fclose(file);
    return 1;
              }

              pe_print_sections(file, &coff);
              pe_print_imports(file, &coff, dos.e_lfanew);
              pe_print_exports(file, &coff, dos.e_lfanew);
              pe_print_relocations(file, &coff, dos.e_lfanew);
              pe_print_utf16_strings(file);
              pe_print_driver_profile(file, &coff, dos.e_lfanew);
              pe_print_abi_profile(file, &coff, dos.e_lfanew);
              pe_disasm_x64(file, &coff, dos.e_lfanew);
              pe_find_calls(file, &coff, dos.e_lfanew);
              fclose(file);

              return 0;
}
