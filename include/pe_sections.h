#ifndef PE_SECTIONS_H
#define PE_SECTIONS_H

#include <stdio.h>
#include "pe.h"

void pe_print_sections(FILE *file, const COFFHeader *coff);

#endif
