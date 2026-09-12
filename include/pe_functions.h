#ifndef PE_FUNCTIONS_H
#define PE_FUNCTIONS_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "pe.h"

typedef struct {
    uint32_t begin_address;
    uint32_t end_address;
    uint32_t unwind_info;
} RuntimeFunction;

typedef struct {
    RuntimeFunction *items;
    size_t count;
} FunctionTable;

int pe_load_functions(FILE *file,
                      const COFFHeader *coff,
                      uint32_t pe_offset,
                      FunctionTable *table);

void pe_free_functions(FunctionTable *table);

void pe_print_functions(const FunctionTable *table);

#endif
