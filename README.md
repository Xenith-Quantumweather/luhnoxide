# Luhnoxide

A high-performance credit card scanner written in Rust that uses the Luhn algorithm to identify valid credit card numbers in files or directories.

## Features

- **Luhn Algorithm Validation**: Accurately identifies valid credit card numbers
- **Card Brand Identification**: Recognizes Visa, Mastercard, American Express, Discover, JCB, Diners Club, and UnionPay
- **Detailed Output**: Shows file path, line number, card brand, BIN, last four digits, and PAN length
- **Secure Display**: Masks middle digits of credit card numbers for security
- **Recursive Directory Scanning**: Process entire directory trees with a single command
- **Multi-threaded Performance**: Utilizes parallel processing for faster scanning of multiple files
- **Flexible Output Options**: Display results on console or save to a file

## Installation

### Prerequisites
- Rust and Cargo installed ([Install Rust](https://www.rust-lang.org/tools/install))

### Building from source
```bash
# Clone the repository
git clone https://github.com/yourusername/luhnoxide.git
cd luhnoxide

# Build the release version
cargo build --release

# The executable will be available at
# ./target/release/luhn_checker
```

## Usage

```bash
# Basic usage - scan a file and display results on console
./luhn_checker -i /path/to/file.txt

# Scan multiple files (comma-separated)
./luhn_checker -i /path/to/file1.txt,/path/to/file2.txt

# Scan a directory recursively
./luhn_checker -i /path/to/directory

# Output results to a file
./luhn_checker -i /path/to/input -o results.txt

# Disable masking of middle digits (shows full card numbers)
./luhn_checker -i /path/to/input --no-mask
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-i, --input` | Input file or directory paths (comma-separated) |
| `-o, --output` | Output file path (default: console) |
| `--no-mask` | Disable masking of middle digits in credit card numbers |

## Output Format

For each identified credit card number, the program displays:
- File path
- Line number
- Card brand (Visa, Mastercard, etc.)
- PAN length (13-19 digits)
- BIN (first 6 digits)
- Last four digits
- Masked PAN (e.g., 411111XXXXXX1111)
- The line content where the card was found

## Security Note

This tool is designed for security professionals to identify exposed credit card numbers in files. Please use responsibly and in accordance with applicable privacy laws and regulations.

The default masking behavior helps prevent accidental exposure of sensitive information in logs or reports.

## License

MIT License

## Contributing

Contributions, issues, and feature requests are welcome!
