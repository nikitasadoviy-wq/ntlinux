#ifndef PE_EXPORTS_H
#define PE_EXPORTS_H

#include <stdio.h>
#include "pe.h"

void pe_print_exports(FILE *file,
                      const COFFHeader *coff,
                      uint32_t pe_offset);

#endif
