#ifndef PE_ABI_H
#define PE_ABI_H

#include <stdio.h>
#include "pe.h"

void pe_print_abi_profile(FILE *file,
                                                    const COFFHeader *coff,
                                                    uint32_t pe_offset);

#endif
