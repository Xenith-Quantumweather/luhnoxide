# Luhnoxide

A high-performance credit card scanner written in Rust that uses the Luhn algorithm to identify valid credit card numbers in files or directories.

## Report Features

The HTML and summary reports include valuable metrics for auditing and compliance:

- **Key Statistics**: Files scanned, directories traversed, total size processed
- **Card Distribution**: Breakdown of found card types (Visa, Mastercard, etc.)
- **Risk Assessment**: Categorization of files by risk level (high, medium, low)
- **Clean File Percentage**: Percentage of files free from credit card data
- **File Listing**: Lists of files containing credit card numbers, organized by risk level
- **Compliance Metrics**: Summary information suitable for PCI DSS reports
- **Visual Presentation**: Formatted for clarity and professional presentation

These reports are particularly useful for:
- Payment Card Industry Data Security Standard (PCI DSS) compliance audits
- Security assessments and penetration test reports
- Client deliverables and executive summaries
- Remediation planning and prioritization

## Features

- **Luhn Algorithm Validation**: Accurately identifies valid credit card numbers
- **Card Brand Identification**: Recognizes Visa, Mastercard, American Express, Discover, JCB, Diners Club, and UnionPay
- **Detailed Output**: Shows file path, line number, card brand, BIN, last four digits, and PAN length
- **Secure Display**: Masks middle digits of credit card numbers for security
- **Recursive Directory Scanning**: Process entire directory trees with a single command
- **Multi-threaded Performance**: Utilizes parallel processing for faster scanning of multiple files
- **Flexible Output Options**: Display results on console or save to a file
- **Comprehensive Reporting**: Generate summary reports for compliance and risk assessment

## Installation

### Prerequisites
- Rust and Cargo installed ([Install Rust](https://www.rust-lang.org/tools/install))

### Building from source
```bash
# Clone the repository
git clone https://github.com/Xenith-Quantumweather/luhnoxide.git
cd luhnoxide

# Build the release version
cargo build --release

# The executable will be available at
# ./target/release/luhnoxide
```

## Usage

```bash
# Basic usage - scan a file and display results on console
./luhnoxide -i /path/to/file.txt

# Scan multiple files (comma-separated)
./luhnoxide -i /path/to/file1.txt,/path/to/file2.txt

# Scan a directory recursively
./luhnoxide -i /path/to/directory

# Output results to a file
./luhnoxide -i /path/to/input -o results.txt

# Disable masking of middle digits (shows full card numbers)
./luhnoxide -i /path/to/input --no-mask

# Output in JSON format
./luhnoxide -i /path/to/input -f json

# Output in CSV format
./luhnoxide -i /path/to/input -f csv -o results.csv

# Generate a summary report with the detailed results
./luhn_checker -i /path/to/input -s

# Generate an HTML report (good for client deliverables)
./luhn_checker -i /path/to/directory -f html -o report.html

# Generate a PDF-ready HTML report
./luhn_checker -i /path/to/directory -f pdf -o report.html

# Combine options: JSON output to file with full card numbers
./luhnoxide -i /path/to/input -f json -o results.json --no-mask
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-i, --input` | Input file or directory paths (comma-separated) |
| `-o, --output` | Output file path (default: console) |
| `-f, --format` | Output format: text (default), json, or csv |
| `-s, --summary` | Generate a summary report of findings |
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

Apache-2.0 License

## Contributing

Contributions, issues, and feature requests are welcome!
