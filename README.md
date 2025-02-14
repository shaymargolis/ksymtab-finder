# ELF Creator and Ksymtab Finder 🎯

This repository contains a set of Python tools designed to interact with Linux kernel binary files. It allows you to find kernel symbols and create ELF files by adding the symbols into the ELF. The primary functionalities include parsing kernel symbols, creating ELF files from binary files, and identifying symbol tables using different methods.

## 🛠️ Features

- **ELF File Creation**: Converts a raw binary file into an ELF file with custom kernel symbols.
- **Kernel Symbol Finder**: Finds kernel symbols using two methods: **normal ksymtab** and **rel32 ksymtab**.
- **Symbol Table Parsing**: Extracts kernel symbols from a kernel binary by parsing ksymtab or rel32 ksymtab entries.
- **Flexible Architecture Support**: Supports various architecture types and bit-sizes (32-bit or 64-bit).
- **Kernel Binary Analysis**: Handles different kernel versions and endian formats for accurate symbol extraction.

## 📝 Installation

You will need `python3` and the following dependencies:

```bash
pip install construct click
```

Make sure you have the necessary permissions to access kernel binaries on your system.

## 🚀 Usage

Run the script to process kernel binary files and generate ELF files with added symbols:

### Create ELF File with Symbols

```bash
python ksymtab_finder.py <kernel_binary_file> --architecture <arch> --linux-ver-override <version> --ksymtab-type <type>
```

### Options:
- **`filename`**: The path to the kernel binary file.
- **`--architecture`**: Override architecture (e.g., `x86_64`, `arm64`). If not provided, the script attempts to detect the architecture automatically.
- **`--linux-ver-override`**: Specify a custom Linux version (default: `5.4.0`).
- **`--ksymtab-type`**: Choose the method to find kernel symbols:
  - `normal`: Standard ksymtab search.
  - `rel32`: Rel32 ksymtab search.

### Example

```bash
python ksymtab_finder.py /path/to/kernel --architecture x86_64 --ksymtab-type normal
```

This command will search for kernel symbols in the specified kernel binary and generate an ELF file (`kernel.elf`) with those symbols added.

## 📜 Use Cases

### 1. **Kernel Debugging and Reverse Engineering 🕵️‍♂️**
   If you're debugging a kernel module or analyzing the kernel's inner workings, this tool can be used to find symbols and generate ELF files to assist with symbol resolution in disassemblers.

### 2. **ELF File Creation for Custom Kernel Versions 🔧**
   Customize your kernel by adding specific function symbols to ELF files. This is especially useful when modifying or extending the kernel code and you need to ensure correct symbol mapping.

### 3. **Exploring Kernel Binary Layout 🧩**
   Understanding how kernel symbols are laid out in memory can aid in reverse engineering or understanding the kernel's internals.

### 4. **Symbol Table Management for Kernel Developers 👨‍💻**
   Kernel developers working on custom builds or kernel modules can use these tools to extract and inject kernel symbols efficiently.

## 📂 File Descriptions

### `elf_creator.py`
- Provides functionality to create ELF files by adding symbols to kernel binaries.
- **Key Function**: `create_elf()` generates the ELF file and adds kernel symbols.

### `find_ksymtab.py`
- Contains logic for parsing the kernel's ksymtab (symbol table).
- **Key Function**: `find_ksymtab()` searches for kernel symbols in the binary.

### `find_rel32_ksymtab.py`
- Similar to `find_ksymtab.py`, but specifically handles finding symbols using the **rel32** method.
- **Key Function**: `find_ksymtab()` searches for symbols and identifies rel32 matches.

### `kernel_accessor.py`
- Defines the `KernelBlobFile` class which reads the kernel binary and provides methods for extracting symbols, values, and strings.
- **Key Function**: `get_string()` retrieves a null-terminated string from the kernel binary.

### `ksymtab_finder.py`
- The main entry point that ties together the ELF creation and symbol finding process. It invokes the relevant classes and functions to process the kernel binary.
- **Key Function**: `ksymtab_finder()` executes the process of finding symbols and creating ELF files.

## 🔧 Development

1. Clone the repository to your local machine:

   ```bash
   git clone <repo_url>
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. You can now run the script to process kernel binaries and generate ELF files!

## 💬 Contributing

We welcome contributions! If you find bugs or have new ideas, feel free to create an issue or submit a pull request.

### Code Style ✨
- Follow PEP 8 guidelines for Python code.
- Ensure proper docstrings are added to functions and classes.

---

Happy kernel symbol finding and ELF creation! 🎉
