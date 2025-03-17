use clap::{App, Arg};
use regex::Regex;
use std::fs::{self, File};
use std::io::{self, BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

// Define credit card brand information
struct CardBrand {
    name: &'static str,
    pattern: &'static str,
    lengths: &'static [usize],
}

// Credit card patterns
const CARD_BRANDS: &[CardBrand] = &[
    CardBrand {
        name: "Visa",
        pattern: r"^4\d+",
        lengths: &[13, 16, 19],
    },
    CardBrand {
        name: "Mastercard",
        pattern: r"^5[1-5]\d+|^2[2-7]\d+",
        lengths: &[16],
    },
    CardBrand {
        name: "American Express",
        pattern: r"^3[47]\d+",
        lengths: &[15],
    },
    CardBrand {
        name: "Discover",
        pattern: r"^6(?:011|5\d{2}|4[4-9]\d)\d+",
        lengths: &[16, 19],
    },
    CardBrand {
        name: "JCB",
        pattern: r"^35\d+",
        lengths: &[16, 19],
    },
    CardBrand {
        name: "Diners Club",
        pattern: r"^3(?:0[0-5]|[68]\d)\d+",
        lengths: &[14, 16, 19],
    },
    CardBrand {
        name: "UnionPay",
        pattern: r"^62\d+",
        lengths: &[16, 19],
    },
    CardBrand {
        name: "Unknown",
        pattern: r"^\d+",
        lengths: &[13, 14, 15, 16, 17, 18, 19],
    },
];

// Structure to hold card findings
#[derive(Clone)]
struct CardMatch {
    brand: String,
    full_pan: String,
    bin: String,
    last_four: String,
    length: usize,
    file_path: String,
    line_number: usize,
    line_content: String,
}

impl CardMatch {
    fn to_string(&self) -> String {
        format!(
            "File: {}\nLine: {}\nBrand: {}\nPAN Length: {}\nBIN: {}\nLast Four: {}\nLine Content: {}\n",
            self.file_path,
            self.line_number,
            self.brand,
            self.length,
            self.bin,
            self.last_four,
            self.line_content.trim()
        )
    }
}

// Implement the Luhn algorithm for credit card validation
fn is_valid_luhn(number: &str) -> bool {
    let mut sum = 0;
    let mut double = false;

    // Iterate from right to left
    for c in number.chars().rev() {
        if let Some(digit) = c.to_digit(10) {
            let mut value = digit;
            if double {
                value *= 2;
                if value > 9 {
                    value -= 9;
                }
            }
            sum += value;
            double = !double;
        } else {
            return false; // Not a digit
        }
    }

    sum % 10 == 0 && sum > 0
}

// Determine the card brand based on pattern and length
fn identify_card_brand(number: &str) -> Option<&'static str> {
    let cleaned_number = number.replace(['-', ' '], "");
    
    for brand in CARD_BRANDS {
        if let Ok(re) = Regex::new(brand.pattern) {
            if re.is_match(&cleaned_number) && brand.lengths.contains(&cleaned_number.len()) {
                return Some(brand.name);
            }
        }
    }
    None
}

// Scan a single file for credit card numbers
fn scan_file(file_path: &Path, results: &Arc<Mutex<Vec<CardMatch>>>) -> io::Result<()> {
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);
    
    // Pattern to find potential credit card numbers with optional separators
    let card_pattern = Regex::new(r"(?:^|\D)([0-9](?:[0-9-\s]){11,18}[0-9])(?:\D|$)").unwrap();

    for (line_number, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        
        for cap in card_pattern.captures_iter(&line) {
            if let Some(matched) = cap.get(1) {
                let potential_card = matched.as_str().replace(['-', ' '], "");
                
                // Check if the number is a valid length and passes Luhn
                if (13..=19).contains(&potential_card.len()) && is_valid_luhn(&potential_card) {
                    if let Some(brand) = identify_card_brand(&potential_card) {
                        let match_details = CardMatch {
                            brand: brand.to_string(),
                            full_pan: potential_card.clone(),
                            bin: potential_card.chars().take(6).collect(),
                            last_four: potential_card.chars().rev().take(4).collect::<String>().chars().rev().collect(),
                            length: potential_card.len(),
                            file_path: file_path.to_string_lossy().to_string(),
                            line_number: line_number + 1,
                            line_content: line.clone(),
                        };
                        
                        if let Ok(mut results_vec) = results.lock() {
                            results_vec.push(match_details);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// Recursively collect files from a directory
fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                collect_files(&path, files)?;
            } else {
                files.push(path);
            }
        }
    } else {
        files.push(path.to_path_buf());
    }
    
    Ok(())
}

fn main() -> io::Result<()> {
    let matches = App::new("Credit Card Luhn Checker")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("Scans files for valid credit card numbers using the Luhn algorithm")
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .value_name("INPUT")
                .help("Input file or directory paths (comma-separated)")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("OUTPUT")
                .help("Output file path (default: console)")
                .takes_value(true),
        )
        .get_matches();

    // Parse input paths
    let input_paths_str = matches.value_of("input").unwrap();
    let input_paths: Vec<&str> = input_paths_str.split(',').collect();
    
    // Collect all files to scan
    let mut files_to_scan: Vec<PathBuf> = Vec::new();
    for input_path in input_paths {
        let path = Path::new(input_path);
        collect_files(path, &mut files_to_scan)?;
    }
    
    // Thread-safe storage for results
    let results = Arc::new(Mutex::new(Vec::new()));
    
    // Process files in parallel
    let mut handles = vec![];
    for file_path in files_to_scan {
        let results_clone = Arc::clone(&results);
        let handle = thread::spawn(move || {
            if let Err(e) = scan_file(&file_path, &results_clone) {
                eprintln!("Error scanning file {:?}: {}", file_path, e);
            }
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Output results
    if let Some(output_path) = matches.value_of("output") {
        let output_file = File::create(output_path)?;
        let mut writer = BufWriter::new(output_file);
        
        if let Ok(results_vec) = results.lock() {
            for card_match in results_vec.iter() {
                writeln!(writer, "{}\n", card_match.to_string())?;
            }
        }
        
        println!("Results written to {}", output_path);
    } else {
        // Output to console
        if let Ok(results_vec) = results.lock() {
            println!("Found {} potential credit card numbers:", results_vec.len());
            
            for card_match in results_vec.iter() {
                println!("{}\n", card_match.to_string());
            }
        }
    }
    
    Ok(())
}
