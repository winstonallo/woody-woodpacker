C_FILES := main.c elf_header.c elf_segments.c elf_sections.c encrypt.c inject.c utils/fd.c utils/memcpy.c utils/put_str.c
SRC_DIRECTORY := src/

COMPILE_C_FILES := $(addprefix $(SRC_DIRECTORY), $(C_FILES))

all:
	@nasm -f elf64 src/stub/decrypt.asm -o stub.o
	@objcopy -O binary stub.o stub.bin
	@echo "// Auto-generated stub code" > stub_bytes.h
	@echo "unsigned char decryption_stub[] = {" >> stub_bytes.h
	@xxd -i < stub.bin | sed 's/^/	/' >> stub_bytes.h
	@echo "};" >> stub_bytes.h
	@cc $(COMPILE_C_FILES) -g -o woody_woodpacker -Iinc

fclean:
	rm woody woody_woodpacker crypto.bin crypto.o stub_bytes.h
