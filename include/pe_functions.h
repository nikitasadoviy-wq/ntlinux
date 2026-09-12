#ifndef PE_FUNCTIONS_H
#define PE_FUNCTIONS_H

#include <stdio.h>
#include <stdint.h>

#include "pe.h"

void pe_print_functions(FILE *file,
                        const COFFHeader *coff,
                        uint32_t pe_offset);

#endif
