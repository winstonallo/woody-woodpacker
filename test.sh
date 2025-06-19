#!/bin/bash

gcc -c -fPIC -fno-stack-protector -nostdlib -static stub/stub.c -o crypto.o

objcopy -O binary --only-section=.text crypto.o crypto.bin

echo "// Auto-generated stub code" > stub_bytes.h
echo "unsigned char decryption_stub[] = {" >> stub_bytes.h
xxd -i < crypto.bin | sed 's/^/    /' >> stub_bytes.h
echo "};" >> stub_bytes.h
