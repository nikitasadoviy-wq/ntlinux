#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pe_abi.h"

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

static int import_matches(const char *name,
                          const char *prefix)
{
    return strncmp(name,
                   prefix,
                   strlen(prefix)) == 0;
}

static void classify_import(const char *name,
                            int *memory,
                            int *io,
                            int *cache,
                            int *fsrtl,
                            int *sync,
                            int *registry,
                            int *pnp,
                            int *power,
                            int *wmi,
                            int *etw,
                            int *security,
                            int *process,
                            int *object)
{
    /*
     * Memory
     */
    if (import_matches(name, "Mm") ||
        import_matches(name, "ExAllocatePool") ||
        import_matches(name, "ExFreePool") ||
        import_matches(name, "ExInitializeLookasideList") ||
        import_matches(name, "ExDeleteLookasideList")) {

        *memory = 1;
        }

        /*
         * I/O / IRP
         */
        if (import_matches(name, "Io") ||
            import_matches(name, "Iof")) {

            *io = 1;
            }

            /*
             * Cache Manager
             */
            if (import_matches(name, "Cc")) {
                *cache = 1;
            }

            /*
             * File System Runtime
             */
            if (import_matches(name, "FsRtl")) {
                *fsrtl = 1;
            }

            /*
             * Synchronization
             */
            if (import_matches(name, "Ke") ||
                import_matches(name, "ExAcquire") ||
                import_matches(name, "ExRelease") ||
                import_matches(name, "ExInitialize")) {

                *sync = 1;
                }

                /*
                 * Registry
                 */
                if (import_matches(name, "ZwOpenKey") ||
                    import_matches(name, "ZwCreateKey") ||
                    import_matches(name, "ZwQueryKey") ||
                    import_matches(name, "ZwQueryValueKey") ||
                    import_matches(name, "ZwSetValueKey") ||
                    import_matches(name, "ZwDeleteKey")) {

                    *registry = 1;
                    }

                    /*
                     * PnP
                     */
                    if (strstr(name, "PlugPlay") ||
                        strstr(name, "PnP") ||
                        strstr(name, "DeviceInterface")) {

                        *pnp = 1;
                        }

                        /*
                         * Power
                         */
                        if (strstr(name, "Power") ||
                            strcmp(name, "PoCallDriver") == 0) {

                            *power = 1;
                            }

                            /*
                             * WMI
                             */
                            if (strncmp(name, "Wmi", 3) == 0 ||
                                strncmp(name, "WMI", 3) == 0) {

                                *wmi = 1;
                                }

                                /*
                                 * ETW
                                 */
                                if (strncmp(name, "Etw", 3) == 0) {
                                    *etw = 1;
                                }

                                /*
                                 * Security / tokens
                                 */
                                if (strncmp(name, "Se", 2) == 0 ||
                                    strstr(name, "Token") ||
                                    strstr(name, "Impersonat")) {

                                    *security = 1;
                                    }

                                    /*
                                     * Processes / threads
                                     */
                                    if (strncmp(name, "Ps", 2) == 0 ||
                                        strstr(name, "Thread") ||
                                        strstr(name, "Process")) {

                                        *process = 1;
                                        }

                                        /*
                                         * Object Manager
                                         */
                                        if (strncmp(name, "Ob", 2) == 0 ||
                                            strstr(name, "Object")) {

                                            *object = 1;
                                            }
}

static void print_mark(const char *name, int used)
{
    printf("      [%c] %s\n",
           used ? 'x' : ' ',
           name);
}

void pe_print_abi_profile(FILE *file,
                          const COFFHeader *coff,
                          uint32_t pe_offset)
{
    printf("\n[+] NT ABI analysis:\n");

    int memory = 0;
    int io = 0;
    int cache = 0;
    int fsrtl = 0;
    int sync = 0;
    int registry = 0;
    int pnp = 0;
    int power = 0;
    int wmi = 0;
    int etw = 0;
    int security = 0;
    int process = 0;
    int object = 0;

    long optional_offset =
    (long)pe_offset +
    4 +
    sizeof(COFFHeader);

    if (fseek(file, optional_offset, SEEK_SET) != 0) {
        printf("[-] Cannot seek Optional Header\n");
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

        uint32_t directory_offset;

        if (magic == 0x20B)
            directory_offset = 0x70;
    else if (magic == 0x10B)
        directory_offset = 0x60;
    else {
        printf("[-] Unknown PE format\n");
        free(optional_header);
        return;
    }

    /*
     * Import Directory = Data Directory #1.
     */
    uint32_t import_directory =
    directory_offset + 8;

    if (import_directory + 8 >
        coff->size_of_optional_header) {

        printf("[-] No Import Directory\n");
    free(optional_header);
    return;
        }

        uint32_t import_rva;

        memcpy(&import_rva,
               optional_header + import_directory,
               sizeof(import_rva));

        free(optional_header);

        if (import_rva == 0) {
            printf("[-] No imports\n");
            return;
        }

        uint32_t import_offset =
        rva_to_file_offset(file,
                           coff,
                           pe_offset,
                           import_rva);

        if (import_offset == 0) {
            printf("[-] Cannot locate Import Directory\n");
            return;
        }

        uint32_t descriptor_offset =
        import_offset;

        while (1) {

            if (fseek(file,
                descriptor_offset,
                SEEK_SET) != 0)
                break;

            ImportDescriptor descriptor;

            if (fread(&descriptor,
                sizeof(descriptor),
                      1,
                      file) != 1)
                break;

            if (descriptor.characteristics == 0 &&
                descriptor.time_date_stamp == 0 &&
                descriptor.forwarder_chain == 0 &&
                descriptor.name == 0 &&
                descriptor.first_thunk == 0) {

                break;
                }

                /*
                 * Читаємо DLL name.
                 */
                uint32_t dll_offset =
                rva_to_file_offset(file,
                                   coff,
                                   pe_offset,
                                   descriptor.name);

                if (dll_offset == 0) {
                    descriptor_offset +=
                    sizeof(ImportDescriptor);
                    continue;
                }

                char dll_name[256];

                if (fseek(file,
                    dll_offset,
                    SEEK_SET) != 0) {
                    descriptor_offset +=
                    sizeof(ImportDescriptor);
                continue;
                    }

                    size_t pos = 0;

                    while (pos + 1 < sizeof(dll_name)) {

                        int c = fgetc(file);

                        if (c == EOF || c == '\0')
                            break;

                        dll_name[pos++] = (char)c;
                    }

                    dll_name[pos] = '\0';

                    /*
                     * Нас цікавлять усі DLL,
                     * але ABI WinNT переважно сидить
                     * у ntoskrnl.exe та пов'язаних модулях.
                     */
                    printf("\n    [%s]\n", dll_name);

                    uint32_t thunk_rva =
                    descriptor.characteristics;

                    if (thunk_rva == 0)
                        thunk_rva = descriptor.first_thunk;

            uint32_t thunk_offset =
            rva_to_file_offset(file,
                               coff,
                               pe_offset,
                               thunk_rva);

            if (thunk_offset == 0) {
                descriptor_offset +=
                sizeof(ImportDescriptor);
                continue;
            }

            uint32_t thunk_size =
            (magic == 0x20B) ? 8 : 4;

            for (uint32_t index = 0;; index++) {

                uint64_t thunk_value = 0;

                if (fseek(file,
                    thunk_offset +
                    index * thunk_size,
                    SEEK_SET) != 0)
                    break;

                if (magic == 0x20B) {

                    if (fread(&thunk_value,
                        sizeof(uint64_t),
                              1,
                              file) != 1)
                        break;

                } else {

                    uint32_t value32;

                    if (fread(&value32,
                        sizeof(value32),
                              1,
                              file) != 1)
                        break;

                    thunk_value = value32;
                }

                if (thunk_value == 0)
                    break;

                uint64_t ordinal_flag =
                (magic == 0x20B)
                ? (1ULL << 63)
                : (1ULL << 31);

                /*
                 * Ordinal import нам для ABI
                 * classification не допоможе.
                 */
                if (thunk_value & ordinal_flag)
                    continue;

                uint32_t name_rva =
                (uint32_t)(thunk_value &
                0xFFFFFFFF);

                uint32_t name_offset =
                rva_to_file_offset(file,
                                   coff,
                                   pe_offset,
                                   name_rva);

                if (name_offset == 0)
                    continue;

                if (fseek(file,
                    name_offset + 2,
                    SEEK_SET) != 0)
                    continue;

                char function_name[256];

                pos = 0;

                while (pos + 1 < sizeof(function_name)) {

                    int c = fgetc(file);

                    if (c == EOF || c == '\0')
                        break;

                    function_name[pos++] =
                    (char)c;
                }

                function_name[pos] = '\0';

                classify_import(function_name,
                                &memory,
                                &io,
                                &cache,
                                &fsrtl,
                                &sync,
                                &registry,
                                &pnp,
                                &power,
                                &wmi,
                                &etw,
                                &security,
                                &process,
                                &object);
            }

            descriptor_offset +=
            sizeof(ImportDescriptor);
        }

        printf("\n    Categories:\n");

        print_mark("Memory", memory);
        print_mark("I/O / IRP", io);
        print_mark("Cache Manager", cache);
        print_mark("File System Runtime", fsrtl);
        print_mark("Synchronization", sync);
        print_mark("Registry", registry);
        print_mark("PnP", pnp);
        print_mark("Power", power);
        print_mark("WMI", wmi);
        print_mark("ETW", etw);
        print_mark("Security", security);
        print_mark("Processes / Threads", process);
        print_mark("Object Manager", object);
}
