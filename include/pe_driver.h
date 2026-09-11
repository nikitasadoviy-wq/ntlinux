#ifndef PE_DRIVER_H
#define PE_DRIVER_H

#include <stdio.h>
#include "pe.h"

void pe_print_driver_profile(FILE *file,
                             const COFFHeader *coff,
                             uint32_t pe_offset);

#endif
