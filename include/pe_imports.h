#ifndef PE_IMPORTS_H
#define PE_IMPORTS_H

#include <stdio.h>
#include "pe.h"

void pe_print_imports(FILE *file,
                      const COFFHeader *coff,
                      uint32_t pe_offset);

#endif
