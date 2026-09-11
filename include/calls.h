#ifndef CALLS_H
#define CALLS_H

#include <stdio.h>
#include "pe.h"

void pe_find_calls(FILE *file,
                   const COFFHeader *coff,
                   uint32_t pe_offset);

#endif
