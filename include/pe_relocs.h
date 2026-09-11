#ifndef PE_RELOCS_H
#define PE_RELOCS_H

#include <stdio.h>
#include "pe.h"

void pe_print_relocations(FILE *file,
                          const COFFHeader *coff,
                          uint32_t pe_offset);

#endif
