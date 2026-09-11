#ifndef PE_H
#define PE_H

#include <stdint.h>

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
    uint8_t reserved[58];
    uint32_t e_lfanew;
} DOSHeader;

typedef struct {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} COFFHeader;

typedef struct {
    uint16_t magic;
    uint8_t data[14];
    uint32_t address_of_entry_point;
} OptionalHeaderStart;

typedef struct {
    uint8_t name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
} SectionHeader;

#pragma pack(pop)

#endif
