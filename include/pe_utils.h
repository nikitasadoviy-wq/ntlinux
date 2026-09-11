#ifndef PE_UTILS_H
#define PE_UTILS_H

#include <stdio.h>
#include "pe.h"

uint32_t pe_rva_to_file_offset(FILE *file,
                               const COFFHeader *coff,
                               uint32_t pe_offset,
                               uint32_t rva);

#endif
