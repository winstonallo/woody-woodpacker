NAME = woody_woodpacker

OBJ_DIR = obj
SRC_DIR = src
INC_DIR = inc
STUB_OBJ_DIR = $(OBJ_DIR)/stub
LIBFT_DIR = libft

BLOCK_SIZE=$(shell stat -fc %s .)

SRCS = \
	utils/fd.c \
	utils/parsehex.c \
	elf_header.c \
	elf_sections.c \
	elf_segments.c \
	encrypt.c \
	inject.c \
	file.c \
	main.c

OBJS = $(addprefix $(OBJ_DIR)/, $(SRCS:.c=.o))

HEADERS = $(wildcard $(INC_DIR)/*.h) $(wildcard $(LIBF_DIR)/src/**/*.h)

LIBFT = $(LIBFT_DIR)/libft.a
LIBFT_FLAGS = -L$(LIBFT_DIR) -lft

CC = cc
CFLAGS = -Wall -Wextra -Werror -I$(INC_DIR) -I$(LIBFT_DIR)/inc -DEXTERNAL_FUNCTIONS_ALLOWED=0
LDFLAGS = $(LIBFT_FLAGS)

all: $(LIBFT) $(NAME)

$(NAME): $(OBJS) $(LIBFT)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME) $(LDFLAGS)

stub_bytes.h: $(SRC_DIR)/stub/decrypt.asm
	@mkdir -p $(STUB_OBJ_DIR)
	@nasm -f elf64 src/stub/decrypt.asm -o $(STUB_OBJ_DIR)/stub.o
	@objcopy -O binary $(STUB_OBJ_DIR)/stub.o $(STUB_OBJ_DIR)/stub.bin
	@echo "// Auto-generated stub code" > stub_bytes.h
	@echo "unsigned char decryption_stub[] = {" >> stub_bytes.h
	@xxd -i < $(STUB_OBJ_DIR)/stub.bin | sed 's/^/	/' >> stub_bytes.h
	@echo "};" >> stub_bytes.h

$(LIBFT):
	$(MAKE) -C $(LIBFT_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c stub_bytes.h $(HEADERS) | $(OBJ_DIR)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)/utils

clean:
	$(MAKE) -C $(LIBFT_DIR) clean
	rm -rf $(OBJ_DIR) stub_bytes.h

fclean: clean
	$(MAKE) -C $(LIBFT_DIR) fclean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
