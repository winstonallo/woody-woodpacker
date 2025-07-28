# woody-woodpacker
⚠️Educational Project⚠️

`woody-woodpacker` is a packer for 64-bit ELF binaries that encrypts their `.text` section and injects a decryption stub to create self-decrypting binaries.

How it works:
1. pack-time
  a. Parses the ELF header, section header, and program headers to find the executable code section
  b. Finds unused space within the binary (=code cave) to inject the decryption stub

## Building
You will need:
* GCC/clang
* NASM
* Make

Alternatively, you can use the [devcontainer config](.devcontainer), which has all requirements pre-installed.

```bash
git clone --recursive git@github.com:winstonallo/woody-woodpacker.git && cd woody-woodpacker
make
```

## Usage
```bash
# Pack a binary with a random key
./woody_woodpacker <binary_file>
# Pack a binary with a specific 16-byte hex key (32 hex characters)
./woody_woodpacker <binary_file> 0123456789abcdef0123456789abcdef
```
The packed binary is saved as `woody`. Since this is an educational project, it will signal that it has been packed by printing `....WOODY....` to stdout before decrypting itself and jumping back to the original code.
### Example
```bash
$ ./woody_woodpacker /bin/ls
$ ./woody
....WOODY....
flag.txt
```
### References
[Practical Binary Analysis, Dennis Andriesse](https://practicalbinaryanalysis.com/)
[ELF Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
