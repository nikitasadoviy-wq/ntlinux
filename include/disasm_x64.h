#ifndef DISASM_X64_H
#define DISASM_X64_H

#include <stdio.h>
#include "pe.h"

void pe_disasm_x64(FILE *file,
                   const COFFHeader *coff,
                   uint32_t pe_offset);

#endif
