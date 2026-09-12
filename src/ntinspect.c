#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pe.h"
#include "pe_sections.h"
#include "pe_imports.h"
#include "pe_exports.h"
#include "pe_relocs.h"
#include "pe_strings.h"
#include "pe_driver.h"
#include "pe_abi.h"
#include "pe_utils.h"
#include "pe_functions.h"
#include "disasm_x64.h"
#include "calls.h"


static void print_help(const char *program)
{
    printf("ntinspect - Windows PE/COFF driver analysis tool\n\n");

    printf("Usage:\n");
    printf("  %s <file.sys> [options]\n\n", program);

    printf("Options:\n");
    printf("  -h, --help       Show this help message\n");
    printf("  --imports        Analyze PE imports\n");
    printf("  --exports        Analyze PE exports\n");
    printf("  --relocs         Analyze base relocations\n");
    printf("  --strings        Scan UTF-16LE strings\n");
    printf("  --abi            Analyze Windows NT API usage\n");
    printf("  --functions      Analyze runtime functions from .pdata\n");
    printf("  --disasm         Disassemble executable sections\n");
    printf("  --calls          Analyze CALL instructions\n");
    printf("  --all            Enable all analysis modules\n");
    printf("  --limit N        Limit displayed CALL instructions\n");
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <file.sys> [options]\n",
                argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-h") == 0 ||
        strcmp(argv[1], "--help") == 0) {

        print_help(argv[0]);
        return 0;
    }

    const char *filename = argv[1];

    int show_imports = 0;
    int show_exports = 0;
    int show_relocs = 0;
    int show_strings = 0;
    int show_abi = 0;
    int show_functions = 0;
    int show_disasm = 0;
    int show_calls = 0;
    int show_all = 0;

    size_t call_limit = 0;

    /*
     * Parse command-line options.
     */
    for (int i = 2; i < argc; i++) {

        if (strcmp(argv[i], "--imports") == 0) {
            show_imports = 1;
        }

        else if (strcmp(argv[i], "--exports") == 0) {
            show_exports = 1;
        }

        else if (strcmp(argv[i], "--relocs") == 0) {
            show_relocs = 1;
        }

        else if (strcmp(argv[i], "--strings") == 0) {
            show_strings = 1;
        }

        else if (strcmp(argv[i], "--abi") == 0) {
            show_abi = 1;
        }

        else if (strcmp(argv[i], "--functions") == 0) {
            show_functions = 1;
        }

        else if (strcmp(argv[i], "--disasm") == 0) {
            show_disasm = 1;
        }

        else if (strcmp(argv[i], "--calls") == 0) {
            show_calls = 1;
        }

        else if (strcmp(argv[i], "--all") == 0) {
            show_all = 1;
        }

        else if (strcmp(argv[i], "--limit") == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr,
                        "Error: --limit requires a number\n");
                return 1;
            }

            char *endptr = NULL;

            unsigned long value =
                strtoul(argv[++i], &endptr, 10);

            if (*endptr != '\0') {
                fprintf(stderr,
                        "Error: invalid limit: %s\n",
                        argv[i]);
                return 1;
            }

            call_limit = (size_t)value;
        }

        else {
            fprintf(stderr,
                    "Error: unknown option: %s\n",
                    argv[i]);

            fprintf(stderr,
                    "Try '%s --help' for more information.\n",
                    argv[0]);

            return 1;
        }
    }

    if (show_all) {
        show_imports = 1;
        show_exports = 1;
        show_relocs = 1;
        show_strings = 1;
        show_abi = 1;
        show_functions = 1;
        show_disasm = 1;
        show_calls = 1;
    }

    FILE *file = fopen(filename, "rb");

    if (!file) {
        perror("fopen");
        return 1;
    }

    DOSHeader dos;

    if (fread(&dos,
              sizeof(dos),
              1,
              file) != 1) {

        fprintf(stderr,
                "Error: failed to read DOS header\n");

        fclose(file);
        return 1;
    }

    if (dos.e_magic != 0x5A4D) {

        fprintf(stderr,
                "Error: invalid MZ signature\n");

        fclose(file);
        return 1;
    }

    if (fseek(file, dos.e_lfanew, SEEK_SET) != 0) {

        perror("fseek PE header");

        fclose(file);
        return 1;
    }

    uint32_t pe_signature;

    if (fread(&pe_signature,
              sizeof(pe_signature),
              1,
              file) != 1) {

        fprintf(stderr,
                "Error: failed to read PE signature\n");

        fclose(file);
        return 1;
    }

    if (pe_signature != 0x00004550) {

        fprintf(stderr,
                "Error: invalid PE signature\n");

        fclose(file);
        return 1;
    }

    COFFHeader coff;

    if (fread(&coff,
              sizeof(coff),
              1,
              file) != 1) {

        fprintf(stderr,
                "Error: failed to read COFF header\n");

        fclose(file);
        return 1;
    }

    printf("[+] PE file: %s\n", filename);

    printf("[+] Machine: 0x%04X\n",
           coff.machine);

    printf("[+] Sections: %u\n",
           coff.number_of_sections);

    printf("[+] Optional Header Size: %u\n",
           coff.size_of_optional_header);

    OptionalHeaderStart optional;

    if (fread(&optional,
              sizeof(optional),
              1,
              file) != 1) {

        fprintf(stderr,
                "Error: failed to read Optional Header\n");

        fclose(file);
        return 1;
    }

    printf("[+] PE Magic: 0x%04X\n",
           optional.magic);

    printf("[+] Entry Point: 0x%08X\n",
           optional.address_of_entry_point);

    if (coff.size_of_optional_header < sizeof(optional)) {

        fprintf(stderr,
                "Error: invalid Optional Header size\n");

        fclose(file);
        return 1;
    }

    if (fseek(file,
              coff.size_of_optional_header - sizeof(optional),
              SEEK_CUR) != 0) {

        perror("fseek remaining Optional Header");

        fclose(file);
        return 1;
    }

    /*
     * Basic analysis.
     */
    pe_print_sections(file,
                      &coff);

    pe_print_driver_profile(file,
                            &coff,
                            dos.e_lfanew);

    /*
     * Optional analysis modules.
     */
    if (show_imports) {
        pe_print_imports(file,
                         &coff,
                         dos.e_lfanew);
    }

    if (show_exports) {
        pe_print_exports(file,
                         &coff,
                         dos.e_lfanew);
    }

    if (show_relocs) {
        pe_print_relocations(file,
                             &coff,
                             dos.e_lfanew);
    }

    if (show_strings) {
        pe_print_utf16_strings(file);
    }

    if (show_abi) {
        pe_print_abi_profile(file,
                             &coff,
                             dos.e_lfanew);
    }

    if (show_functions) {
        FunctionTable function_table;

        if (pe_load_functions(file,
            &coff,
            dos.e_lfanew,
            &function_table)) {

            pe_print_functions(&function_table);
        pe_free_functions(&function_table);

            } else {
                printf("\n[+] Functions:\n");
                printf("    [-] Failed to load .pdata\n");
            }
    }

    if (show_disasm) {
        pe_disasm_x64(file,
                      &coff,
                      dos.e_lfanew);
    }

    if (show_calls) {
        pe_find_calls(file,
                      &coff,
                      dos.e_lfanew,
                      call_limit);
    }

    fclose(file);

    return 0;
}
