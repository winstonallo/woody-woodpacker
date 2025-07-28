# woody-woodpacker
⚠️Educational Project⚠️

`woody-woodpacker` is a packer for 64-bit ELF binaries that encrypts their `.text` section and injects a decryption stub to create self-decrypting binaries.

## How it works:
### When packing the binary (`./woody_woodpacker <binary_file>`):
1. The ELF header, section headers, and program headers are parsed to find the executable code section containing the entry point
2. Unused space is found within the binary to inject the decryption stub without corrupting existing data
3. The `.text` section is obfuscated by encrypting it with a simple XOR Cipher
4. The [decryption stub](src/stub/decrypt.asm) is injected along with some embedded data (decryption key, original entry point offset, size of `.text` section) into the binary
5. The ELF entry point is modified to point to the injected decryption stub
6. The packed binary is written to a new file called `woody`

### When running the packed binary (`./woody`):
1. Execution starts at the decryption stub instead of the original entrypoint
2. `....WOODY....` is printed to stdout to signal that the binary has been packed
3. For Position Independent Executables (PIE), the base address is resolved by parsing `/proc/self/maps`
4. The encrypted code is made writable with `mprotect`
5. The code is decrypted,
6. Memory protection is restored to `PROT_READ | PROT_EXEC` 
7. Control is transferred back to the original entry point

The packer handles both PIE and non-PIE binaries by:
* Detecting the binary types from the ELF headers
* Calculating runtime base addresses for PIE
* Using absolute addresses for non-PIE

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
Found section header including entry point at 0x46b0 - 0x1974e
Found program header of entry point section header at 0x4000 - 0x19759
Found next program header 0x1a000
Found biggest code cave from 0x19759 - 0x1a000

Patched decryption key 57e46388637dcd78a81ed6791988de7a into payload at position 502
Patched entrypoint (0x61d0) into payload
Patched shellcode size (518 bytes) into payload
Patched start address of section to be encrypted (0x46b0) into payload
Patched size of section to be encrypted (0x1509e) into payload

 -- Final Payload --
0x5057 0x5652 0xb801 0x0000 0x00bf 0x0100 0x0000 0x488d 
0x35c3 0x0100 0x00ba 0x0e00 0x0000 0x0f05 0x83f8 0x0e0f 
[...]
0x2f6d 0x6170 0x7300 0x57e4 0x6388 0x637d 0xcd78 0xa81e 
0xd679 0x1988 0xde7a 

Injected patched shellcode into binary at offset 0x19759
$ ./woody
....WOODY....
flag.txt
```

When comparing the `objdump` output of the original binary to `woody`'s, you can see that the `.text` section has been encrypted:
```
(woody-woodpacker) ➜  woody-woodpacker git:(main) ✗ diff --side-by-side a.out.obj woody.obj                        

a.out:     file format elf64-x86-64                           | woody:     file format elf64-x86-64

Disassembly of section .init:                                   Disassembly of section .init:

0000000000001000 <_init>:                                       0000000000001000 <_init>:
    1000:       48 83 ec 08             sub    $0x8,%rsp            1000:       48 83 ec 08             sub    $0x8,%rsp
    1004:       48 8b 05 c5 2f 00 00    mov    0x2fc5(%rip),%       1004:       48 8b 05 c5 2f 00 00    mov    0x2fc5(%rip),%
    100b:       48 85 c0                test   %rax,%rax            100b:       48 85 c0                test   %rax,%rax
    100e:       74 02                   je     1012 <_init+0x       100e:       74 02                   je     1012 <_init+0x
    1010:       ff d0                   call   *%rax                1010:       ff d0                   call   *%rax
    1012:       48 83 c4 08             add    $0x8,%rsp            1012:       48 83 c4 08             add    $0x8,%rsp
    1016:       c3                      ret                         1016:       c3                      ret

[...]

Disassembly of section .text:                                   Disassembly of section .text:

0000000000001050 <_start>:                                      0000000000001050 <_start>:
    1050:       31 ed                   xor    %ebp,%ebp      |     1050:       03 56 ec                add    -0x14(%rsi),%e
    1052:       49 89 d1                mov    %rdx,%r9       |     1053:       88 17                   mov    %dl,(%rdi)
    1055:       5e                      pop    %rsi           |     1055:       f3 da ab df f8 34 0f    repz fisubrl 0xf34f8d
    1056:       48 89 e2                mov    %rsp,%rdx      |     105c:       85 77 f0                test   %esi,-0x10(%rd
    1059:       48 83 e4 f0             and    $0xfffffffffff |     105f:       0e                      (bad)
    105d:       50                      push   %rax           |     1060:       03 7b 94                add    -0x6c(%rbx),%e
    105e:       54                      push   %rsp           |     1063:       c8 8e 20 af             enter  $0x208e,$0xaf
    105f:       45 31 c0                xor    %r8d,%r8d      |     1067:       ec                      in     (%dx),%al
    1062:       31 c9                   xor    %ecx,%ecx      |     1068:       3d b0 b7 14 60          cmp    $0x6014b7b0,%e
    1064:       48 8d 3d ce 00 00 00    lea    0xce(%rip),%rd |     106d:       68 8b 4b 32 4f          push   $0x4f324b8b
    106b:       ff 15 4f 2f 00 00       call   *0x2f4f(%rip)  |     1072:       c3                      ret
    1071:       f4                      hlt                   |     1073:       2f                      (bad)
    1072:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax |     1074:       c9                      leave
    1079:       00 00 00                                      |     1075:       b2 16                   mov    $0x16,%dl
    107c:       0f 1f 40 00             nopl   0x0(%rax)      |     1077:       22 3d b0 b7 eb 7a       and    0x7aebb7b0(%ri
                                                              >     107d:       38 e4                   cmp    %ah,%ah
                                                              >     107f:       4b                      rex.WXB
```

## Limitations
This packer has some more or less intentional limitations:
* XOR cipher is easily reversible
* The `....WOODY....` output makes detection trivial
* The decryption stub pattern is easily recognizable

## References
[Practical Binary Analysis, Dennis Andriesse](https://practicalbinaryanalysis.com/)
[ELF Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
