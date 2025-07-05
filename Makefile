NAME = woody_woodpacker

OBJ_DIR = obj
SRC_DIR = src
INC_DIR = src/inc
STUB_OBJ_DIR = $(OBJ_DIR)/stub

SRCS = \
	utils/fd.c \
	utils/memcpy.c \
	utils/parsehex.c \
	utils/put_str.c \
	elf_header.c \
	elf_sections.c \
	elf_segments.c \
	encrypt.c \
	inject.c \
	main.c

OBJS = $(addprefix $(OBJ_DIR)/, $(SRCS:.c=.o))

HEADERS = $(wildcard $(INC_DIR)/*.h)

CC = cc
CFLAGS = -Wall -Wextra -Werror -I$(INC_DIR)

all: $(NAME)

stub_bytes.h: $(SRC_DIR)/stub/decrypt.asm
	@mkdir -p $(STUB_OBJ_DIR)
	@nasm -f elf64 src/stub/decrypt.asm -o $(STUB_OBJ_DIR)/stub.o
	@objcopy -O binary $(STUB_OBJ_DIR)/stub.o $(STUB_OBJ_DIR)/stub.bin
	@echo "// Auto-generated stub code" > stub_bytes.h
	@echo "unsigned char decryption_stub[] = {" >> stub_bytes.h
	@xxd -i < stub.bin | sed 's/^/	/' >> stub_bytes.h
	@echo "};" >> stub_bytes.h

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c stub_bytes.h $(HEADERS) | $(OBJ_DIR)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)/utils


$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME)

clean:
	rm -rf $(OBJ_DIR) stub_bytes.h

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
