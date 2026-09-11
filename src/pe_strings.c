#include <stdio.h>
#include <stdint.h>
#include <wchar.h>

#include "pe_strings.h"

#define MIN_UTF16_LENGTH 4
#define MAX_UTF16_LENGTH 512

void pe_print_utf16_strings(FILE *file)
{
    printf("\n[+] UTF-16LE Strings:\n");

    if (fseek(file, 0, SEEK_SET) != 0) {
        perror("fseek");
        return;
    }

    uint8_t byte1;
    uint8_t byte2;

    uint16_t string[MAX_UTF16_LENGTH + 1];
    size_t length = 0;

    while (fread(&byte1, 1, 1, file) == 1) {

        if (fread(&byte2, 1, 1, file) != 1)
            break;

        uint16_t ch =
        (uint16_t)byte1 |
        ((uint16_t)byte2 << 8);

        /*
         * Простий фільтр:
         * printable ASCII в UTF-16LE
         * плюс базові Unicode-символи.
         */
        int printable =
        (ch >= 0x20 && ch <= 0x7E);

        if (printable) {

            if (length < MAX_UTF16_LENGTH) {
                string[length++] = ch;
            }

        } else {

            if (length >= MIN_UTF16_LENGTH) {

                printf("    ");

                for (size_t i = 0; i < length; i++) {
                    printf("%c", (char)string[i]);
                }

                printf("\n");
            }

            length = 0;
        }
    }

    /*
     * Рядок міг закінчитися EOF без нульового символу.
     */
    if (length >= MIN_UTF16_LENGTH) {

        printf("    ");

        for (size_t i = 0; i < length; i++) {
            printf("%c", (char)string[i]);
        }

        printf("\n");
    }
}
