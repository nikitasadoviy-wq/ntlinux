CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iinclude
LDLIBS = -lcapstone

TARGET = ntinspect

SRC = \
	src/ntinspect.c \
	src/pe_utils.c \
	src/pe_sections.c \
	src/pe_imports.c \
	src/pe_exports.c \
	src/pe_relocs.c \
	src/pe_strings.c \
	src/pe_driver.c \
	src/pe_abi.c \
	src/disasm_x64.c \
	src/calls.c

OBJ = $(SRC:.c=.o)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

rebuild: clean $(TARGET)

.PHONY: clean rebuild
