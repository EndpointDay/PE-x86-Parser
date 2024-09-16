# PE x86 Parser

A simple Java parser for 32-bit Portable Executable (PE) files. This tool reads and verifies the DOS and PE headers, extracts COFF header information, and provides insights into the structure of PE files.

## Features

- Validates DOS header signature (`MZ`).
- Reads and verifies the PE header signature (`PE\0\0`).
- Extracts and displays COFF header information including:
  - Machine type
  - Number of sections
  - Timestamp
  - Optional header size
- Extracts and displays optional header information including:
  - Image base
  - Entry point
  - Section alignment
  - File alignment
  - Data directories
- Parses and displays section headers, including:
  - Section name
  - Virtual size and address
  - Size of raw data
  - Pointer to raw data
  - Characteristics

## Requirements

- Java 8 or later

## Usage

1. **Compile the Code**

   Make sure you have Java installed, then compile the code using:

   ```bash
   javac Main.java
   ```

2. **Run the Parser**

   Execute the compiled code with:

   ```bash
   java Main
   ```

   You will be prompted to enter the path to the PE file. Provide the full path to a valid 32-bit PE file to see the parsed information.

## Example

```text
Enter the path to the PE file: C:\path\to\file.exe
DOS Signature (MZ) found.
PE Header Offset: 0x40
PE Signature (PE\0\0) found.
Machine: 0x14c
Number of sections: 3
Timestamp: 0x5f3b54a9
Optional Header Size: 224
Image Base: 0x400000
Entry Point: 0x1000
Section Alignment: 0x1000
File Alignment: 0x200
Export Table RVA: 0x0
Import Table RVA: 0x0
Resource Table RVA: 0x0
Exception Table RVA: 0x0
Certificate Table RVA: 0x0
Base Reloc Table RVA: 0x0
Debug Table RVA: 0x0
Architecture Table RVA: 0x0
Global Ptr RVA: 0x0
TLS Table RVA: 0x0
Load Config Table RVA: 0x0
Bound Import Table RVA: 0x0
IAT RVA: 0x0
Delay Import Descriptor RVA: 0x0
CLR Runtime Header RVA: 0x0
Reserved RVA: 0x0
Section Name: .text
Virtual Size: 0x1000
Virtual Address: 0x1000
Size of Raw Data: 0x1000
Pointer to Raw Data: 0x400
Characteristics: 0x60000020
...
