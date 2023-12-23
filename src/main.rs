#![allow(unused)]
use clap::{CommandFactory, Parser};
use elf::endian::AnyEndian;
use elf::file::Class;
use elf::section::SectionHeader;
use elf::ElfBytes;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use rustc_hex::ToHex;
use std::io;
use std::io::Write;
use std::str;

fn read_section(section_offset: u64, section_size: u64, elf_file: &Vec<u8>) -> Vec<u8> {
    return elf_file[section_offset as usize..section_offset as usize + section_size as usize]
        .to_vec();
}

fn print_hex(binary: &Vec<u8>) {
    let hex_str: String = binary.as_slice().to_hex();
    println!("{}", hex_str);
}

fn print_string_shellcode(binary: &Vec<u8>) {
    let hex_str: String = binary.as_slice().to_hex();
    for i in 0..hex_str.len() / 2 {
        print!("\\x{}", &hex_str[i * 2..i * 2 + 2]);
    }
    println!("");
}

fn print_array_shellcode(binary: &Vec<u8>) {
    let hex_str: String = binary.as_slice().to_hex();
    for i in 0..hex_str.len() / 2 {
        if i == 0 {
            print!("0x{}", &hex_str[i * 2..i * 2 + 2]);
        } else {
            print!(", 0x{}", &hex_str[i * 2..i * 2 + 2]);
        }
    }
    println!("");
}

fn print_python_shellcode(binary: &Vec<u8>) {
    let hex_str: String = binary.as_slice().to_hex();
    print!("python3 -c 'import sys; sys.stdout.buffer.write(b\"");
    for i in 0..hex_str.len() / 2 {
        print!("\\x{}", &hex_str[i * 2..i * 2 + 2]);
    }
    println!("\")'");
}

fn stdout_shellcode(binary: &Vec<u8>) {
    let mut writer = io::BufWriter::new(io::stdout());
    writer.write_all(&binary.as_slice());
}

fn disassembled_shellcode(binary: &Vec<u8>, bit: u32) {
    let mut decoder = Decoder::with_ip(bit, binary.as_slice(), 0, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    while decoder.can_decode() {
        // There's also a decode() method that returns an instruction but that also
        // means it copies an instruction (40 bytes):
        //     instruction = decoder.decode();
        decoder.decode_out(&mut instruction);

        // Format the instruction ("disassemble" it)
        output.clear();
        formatter.format(&instruction, &mut output);

        println!(" {}", output);
    }
}

/// Read text section bytes and format it.
/// Without option, it just print text section bytes.
#[derive(Debug, Parser)]
#[clap(verbatim_doc_comment)]
struct Args {
    /// Ex: \x55\x48\x89\xe5\x48
    #[clap(long, short, action)]
    string_mode: bool,

    /// Ex: 0x55, 0x48, 0x89, 0xe5, 0x48
    #[clap(long, short, action)]
    array_mode: bool,

    /// Ex: python3 -c 'import sys; sys.stdout.buffer.write(b"\x55\x48\x89\xe5\x48")'
    #[clap(long, short, action)]
    python_mode: bool,

    /// Ex:{n}push rbp{n}mov rbp,rsp{n}mov rax,3Bh{n}...
    #[clap(long, short, action)]
    disassemble_mode: bool,

    /// Direct stdout. If you choose this option, other option will be ignore.
    #[clap(long, short, action)]
    write_mode: bool,

    file: std::path::PathBuf,
}

fn main() {
    let abnormal_file_error = "Could not read section header. Abnormal ELF file.";
    let not_elf_file_error = "Could not read file as ELF. Maybe not ELF file.";
    let args = Args::parse();
    let mut cmd = Args::command();

    ////// read elf file
    let elf_file_vec: Vec<u8> = match std::fs::read(&args.file) {
        Ok(r) => r,
        Err(e) => {
            println!("Could not open file.\n{}", e);
            std::process::exit(0);
        }
    };
    let elf_file =
        ElfBytes::<AnyEndian>::minimal_parse(elf_file_vec.as_slice()).expect(not_elf_file_error);

    let bit: u32 = match elf_file.ehdr.class {
        Class::ELF32 => 32,
        Class::ELF64 => 64,
    };

    let text_shdr: SectionHeader = elf_file
        .section_header_by_name(".text")
        .expect(&abnormal_file_error)
        .expect(&abnormal_file_error);

    let text_section = read_section(text_shdr.sh_offset, text_shdr.sh_size, &elf_file_vec);

    ////// execute command
    if args.write_mode {
        stdout_shellcode(&text_section);
        return;
    }

    let mut arg_rem = args.array_mode as u8
        + args.python_mode as u8
        + args.string_mode as u8
        + args.disassemble_mode as u8;

    if arg_rem == 0 {
        print_hex(&text_section);
        return;
    }

    if args.string_mode {
        print_string_shellcode(&text_section);

        //// if not last, line break
        arg_rem -= 1;
        if arg_rem != 0 {
            println!();
        }
    }

    if args.array_mode {
        print_array_shellcode(&text_section);

        //// if not last, line break
        arg_rem -= 1;
        if arg_rem != 0 {
            println!();
        }
    }

    if args.python_mode {
        print_python_shellcode(&text_section);

        //// if not last, line break
        arg_rem -= 1;
        if arg_rem != 0 {
            println!();
        }
    }
    if args.disassemble_mode {
        disassembled_shellcode(&text_section, bit);

        //// if not last, line break
        arg_rem -= 1;
        if arg_rem != 0 {
            println!();
        }
    }

    return;
}
