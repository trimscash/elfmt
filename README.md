# elfmt
Read text section bytes and format it for shellcode.

![image](https://github.com/trimscash/elfmt/assets/42578480/47c7bf0d-bb58-4dc4-8e7b-8d7f1cbc7759)

![image](https://github.com/trimscash/elfmt/assets/42578480/a812e920-f819-439a-b6ef-074b1391a1b2)
# Setup
```
git clone https://github.com/trimscash/elfmt ~
cd elfmt
cargo build -r
echo "export PATH=\$PATH:\$HOME/elfmt/target/release" >> ~/.zshrc
source ~/.zshrc
```
and use it. 
Replace .zshrc with the one you are using

# Usage
```
Read text section bytes and format it.
Without option, it just print text section bytes.

Usage: elfmt [OPTIONS] <FILE>

Arguments:
  <FILE>  

Options:
  -s, --string-mode       Ex: \x55\x48\x89\xe5\x48
  -a, --array-mode        Ex: 0x55, 0x48, 0x89, 0xe5, 0x48
  -p, --python-mode       Ex: python3 -c 'import sys; sys.stdout.buffer.write(b"\x55\x48\x89\xe5\x48")'
  -d, --disassemble-mode  Ex:
                          push rbp
                          mov rbp,rsp
                          mov rax,3Bh
                          ...
  -w, --write-mode        Direct stdout. If you choose this option, other option will be ignore
  -h, --help              Print help
```

# Example
```
$ elfmt test.elf
554889e548c7c03b000000488d3c2524104000488d3425361040006a004889e20f05c9c32f62696e2f6361740063617400666c6167002d1040000000000031104000000000000000000000000000
```

```
$ elfmt test.elf -aspd
\x55\x48\x89\xe5\x48\xc7\xc0\x3b\x00\x00\x00\x48\x8d\x3c\x25\x24\x10\x40\x00\x48\x8d\x34\x25\x36\x10\x40\x00\x6a\x00\x48\x89\xe2\x0f\x05\xc9\xc3\x2f\x62\x69\x6e\x2f\x63\x61\x74\x00\x63\x61\x74\x00\x66\x6c\x61\x67\x00\x2d\x10\x40\x00\x00\x00\x00\x00\x31\x10\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00

0x55, 0x48, 0x89, 0xe5, 0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x3c, 0x25, 0x24, 0x10, 0x40, 0x00, 0x48, 0x8d, 0x34, 0x25, 0x36, 0x10, 0x40, 0x00, 0x6a, 0x00, 0x48, 0x89, 0xe2, 0x0f, 0x05, 0xc9, 0xc3, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x63, 0x61, 0x74, 0x00, 0x63, 0x61, 0x74, 0x00, 0x66, 0x6c, 0x61, 0x67, 0x00, 0x2d, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

python3 -c 'import sys; sys.stdout.buffer.write(b"\x55\x48\x89\xe5\x48\xc7\xc0\x3b\x00\x00\x00\x48\x8d\x3c\x25\x24\x10\x40\x00\x48\x8d\x34\x25\x36\x10\x40\x00\x6a\x00\x48\x89\xe2\x0f\x05\xc9\xc3\x2f\x62\x69\x6e\x2f\x63\x61\x74\x00\x63\x61\x74\x00\x66\x6c\x61\x67\x00\x2d\x10\x40\x00\x00\x00\x00\x00\x31\x10\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")'

 push rbp
 mov rbp,rsp
 mov rax,3Bh
 lea rdi,[401024h]
 lea rsi,[401036h]
 push 0
 mov rdx,rsp
 syscall
 leave
 ret
 (bad)
 imul ebp,[rsi+2Fh],746163h
 movsxd esp,[rcx+74h]
 add [rsi+6Ch],ah
 (bad)
 add [rel 404Bh],ch
 add [rax],al
 add [rcx],dh
 adc [rax],al
 add [rax],al
 add [rax],al
 add [rax],al
 add [rax],al
 add [rax],al
 add [rax],al
```

```
$ texthex test.elf -w
UH��H��;H�<%$@H�4%6@jH����/bin/catcatflag-@1@
```
