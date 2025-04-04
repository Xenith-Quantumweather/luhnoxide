use clap::{App, Arg};
use regex::Regex;
use std::fs::{self, File};
use std::io::{self, BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Instant, Duration};
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use chrono;

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
#[derive(Clone, Serialize, Deserialize)]
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
    fn to_string(&self, show_full: bool) -> String {
        let pan_display = if show_full {
            format!("Full PAN: {}", self.full_pan)
        } else {
            format!("Masked PAN: {}", self.masked_pan())
        };
        
        // Create a sanitized version of the line content
        let sanitized_line = if !show_full {
            self.mask_line_content()
        } else {
            self.line_content.clone()
        };
        
        format!(
            "File: {}\nLine: {}\nBrand: {}\nPAN Length: {}\nBIN: {}\nLast Four: {}\n{}\nLine Content: {}\n",
            self.file_path,
            self.line_number,
            self.brand,
            self.length,
            self.bin,
            self.last_four,
            pan_display,
            sanitized_line.trim()
        )
    }
    
    fn masked_pan(&self) -> String {
        // Keep BIN (first 6) and last 4 digits, mask the middle with 'X'
        let masked_middle = "X".repeat(self.length - 10);
        format!("{}{}{}", &self.bin, masked_middle, &self.last_four)
    }
    
    fn mask_line_content(&self) -> String {
        // Create a regex to find the card number in various formats
        let card_digits_only = self.full_pan.clone();
        let mut masked_line = self.line_content.clone();
        
        // Handle cards with no separators
        if masked_line.contains(&card_digits_only) {
            masked_line = masked_line.replace(&card_digits_only, &self.masked_pan());
            return masked_line;
        }
        
        // Handle cards with spaces or dashes
        // Try common formats: groups of 4, groups of 4 with last group of 3-7
        let patterns = [
            // 4-4-4-4 format (16 digits with spaces)
            format!(
                "{} {} {} {}", 
                &card_digits_only[0..4], 
                &card_digits_only[4..8], 
                &card_digits_only[8..12], 
                &card_digits_only[12..16]
            ),
            // 4-4-4-4 format (16 digits with dashes)
            format!(
                "{}-{}-{}-{}", 
                &card_digits_only[0..4], 
                &card_digits_only[4..8], 
                &card_digits_only[8..12], 
                &card_digits_only[12..16]
            ),
        ];
        
        for pattern in patterns {
            if masked_line.contains(&pattern) {
                // For simplicity, replace with masked version without separators
                // A more sophisticated approach would preserve the original format
                masked_line = masked_line.replace(&pattern, &self.masked_pan());
                break;
            }
        }
        
        masked_line
    }
}

// Structure to hold scan statistics and summary
#[derive(Serialize, Deserialize)]
struct ScanSummary {
    scan_date: String,
    scan_duration: String,
    total_files_scanned: usize,
    total_directories_scanned: usize,
    total_files_with_cards: usize,
    total_cards_found: usize,
    clean_files: usize,
    card_type_counts: HashMap<String, usize>,
    files_by_risk: HashMap<String, Vec<String>>,
    skipped_files: Vec<String>,
    total_size_scanned_mb: f64,
    all_scanned_files: Vec<String>, // New field to store all scanned file paths
}

impl ScanSummary {
    fn new() -> Self {
        ScanSummary {
            scan_date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            scan_duration: "0s".to_string(),
            total_files_scanned: 0,
            total_directories_scanned: 0,
            total_files_with_cards: 0,
            total_cards_found: 0,
            clean_files: 0,
            card_type_counts: HashMap::new(),
            files_by_risk: HashMap::from([
                ("high".to_string(), Vec::new()),
                ("medium".to_string(), Vec::new()),
                ("low".to_string(), Vec::new()),
            ]),
            skipped_files: Vec::new(),
            total_size_scanned_mb: 0.0,
            all_scanned_files: Vec::new(),
        }
    }
    
    fn update_duration(&mut self, duration: Duration) {
        let seconds = duration.as_secs();
        if seconds < 60 {
            self.scan_duration = format!("{}s", seconds);
        } else if seconds < 3600 {
            self.scan_duration = format!("{}m {}s", seconds / 60, seconds % 60);
        } else {
            self.scan_duration = format!("{}h {}m {}s", 
                seconds / 3600, 
                (seconds % 3600) / 60, 
                seconds % 60
            );
        }
    }
    
    fn increment_card_type(&mut self, card_type: &str) {
        *self.card_type_counts.entry(card_type.to_string()).or_insert(0) += 1;
    }
    
    fn add_file_by_risk(&mut self, risk_level: &str, file_path: &str) {
        if let Some(files) = self.files_by_risk.get_mut(risk_level) {
            files.push(file_path.to_string());
        }
    }
    
    fn add_scanned_file(&mut self, file_path: &str) {
        self.all_scanned_files.push(file_path.to_string());
    }
    
    // Generate HTML report
    fn to_html(&self) -> String {
        let mut html = String::from(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Luhnoxide Card Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #2c3e50;
            margin-top: 30px;
        }
        .summary-box {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-item {
            background-color: #ffffff;
            border-left: 4px solid #3498db;
            padding: 10px 15px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }
        .stat-label {
            font-size: 14px;
            color: #7f8c8d;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .file-list {
            max-height: 200px;
            overflow-y: auto;
            border: 1px solid #ddd;
            padding: 10px;
            margin-bottom: 20px;
        }
        .risk-high {
            color: #e74c3c;
        }
        .risk-medium {
            color: #f39c12;
        }
        .risk-low {
            color: #2ecc71;
        }
        .footer {
            margin-top: 30px;
            border-top: 1px solid #ddd;
            padding-top: 10px;
            font-size: 12px;
            color: #7f8c8d;
        }
        .chart {
            height: 300px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Luhnoxide Credit Card Scan Report</h1>
        
        <div class="summary-box">
            <p><strong>Scan Date:</strong> "#);
        
        html.push_str(&self.scan_date);
        html.push_str(r#"</p>
            <p><strong>Scan Duration:</strong> "#);
        
        html.push_str(&self.scan_duration);
        html.push_str(r#"</p>
        </div>
        
        <h2>Key Metrics</h2>
        <div class="stat-grid">
            <div class="stat-item">
                <div class="stat-value">"#);
        
        html.push_str(&self.total_files_scanned.to_string());
        html.push_str(r#"</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">"#);
        
        html.push_str(&self.total_directories_scanned.to_string());
        html.push_str(r#"</div>
                <div class="stat-label">Directories Scanned</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">"#);
        
        html.push_str(&self.total_cards_found.to_string());
        html.push_str(r#"</div>
                <div class="stat-label">Card Numbers Found</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">"#);
        
        html.push_str(&self.total_files_with_cards.to_string());
        html.push_str(r#"</div>
                <div class="stat-label">Files Containing Cards</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">"#);
        
        html.push_str(&self.clean_files.to_string());
        html.push_str(r#"</div>
                <div class="stat-label">Clean Files</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">"#);
        
        html.push_str(&format!("{:.2}", self.total_size_scanned_mb));
        html.push_str(r#"</div>
                <div class="stat-label">Total Size (MB)</div>
            </div>
        </div>
        
        <h2>Card Type Distribution</h2>
        <table>
            <tr>
                <th>Card Brand</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>"#);
        
        let total_cards = self.total_cards_found as f64;
        for (brand, count) in &self.card_type_counts {
            let percentage = if total_cards > 0.0 {
                (*count as f64 / total_cards) * 100.0
            } else {
                0.0
            };
            
            html.push_str(&format!(r#"
            <tr>
                <td>{}</td>
                <td>{}</td>
                <td>{:.1}%</td>
            </tr>"#, brand, count, percentage));
        }
        
        html.push_str(r#"
        </table>
        
        <h2>Risk Assessment</h2>"#);
        
        // High Risk Files
        if !self.files_by_risk["high"].is_empty() {
            html.push_str(r#"
        <h3 class="risk-high">High Risk Files</h3>
        <p>Files containing many credit card numbers or highly sensitive data:</p>
        <div class="file-list">"#);
            
            for file in &self.files_by_risk["high"] {
                html.push_str(&format!("<p>{}</p>", file));
            }
            
            html.push_str(r#"
        </div>"#);
        }
        
        // Medium Risk Files
        if !self.files_by_risk["medium"].is_empty() {
            html.push_str(r#"
        <h3 class="risk-medium">Medium Risk Files</h3>
        <p>Files containing some credit card numbers:</p>
        <div class="file-list">"#);
            
            for file in &self.files_by_risk["medium"] {
                html.push_str(&format!("<p>{}</p>", file));
            }
            
            html.push_str(r#"
        </div>"#);
        }
        
        // Low Risk Files
        if !self.files_by_risk["low"].is_empty() {
            html.push_str(r#"
        <h3 class="risk-low">Low Risk Files</h3>
        <p>Files containing few credit card numbers:</p>
        <div class="file-list">"#);
            
            for file in &self.files_by_risk["low"] {
                html.push_str(&format!("<p>{}</p>", file));
            }
            
            html.push_str(r#"
        </div>"#);
        }
        
        // Clean Status
        let clean_percentage = if self.total_files_scanned > 0 {
            (self.clean_files as f64 / self.total_files_scanned as f64) * 100.0
        } else {
            0.0
        };
        
        html.push_str(&format!(r#"
        <h2>Compliance Status</h2>
        <div class="summary-box">
            <p><strong>{:.1}%</strong> of scanned files are free of credit card data.</p>
        </div>
        "#, clean_percentage));
        
        // Add the complete list of scanned files
        html.push_str(r#"
        <h2>Scanned Files</h2>
        <p>Complete list of all scanned files:</p>
        <div class="file-list">"#);
        
        for file in &self.all_scanned_files {
            html.push_str(&format!("<p>{}</p>", file));
        }
        
        html.push_str(r#"
        </div>"#);
        
        if !self.skipped_files.is_empty() {
            html.push_str(r#"
        <h2>Skipped Files</h2>
        <p>Files that could not be processed (binary, permission issues, etc.):</p>
        <div class="file-list">"#);
            
            for file in &self.skipped_files {
                html.push_str(&format!("<p>{}</p>", file));
            }
            
            html.push_str(r#"
        </div>"#);
        }
        
        html.push_str(r#"
        <div class="footer">
            <p>Generated by Luhnoxide - Credit Card Scanner</p>
        </div>
    </div>
</body>
</html>"#);
        
        html
    }
    
    // Generate PDF-friendly HTML
    fn to_pdf_html(&self) -> String {
        // Simplified version for PDF conversion
        self.to_html()
    }
}

// Enumeration for output format
#[derive(Debug, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Csv,
    Html,
    Pdf,
}

impl OutputFormat {
    fn from_str(s: &str) -> OutputFormat {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "csv" => OutputFormat::Csv,
            "html" => OutputFormat::Html,
            "pdf" => OutputFormat::Pdf,
            _ => OutputFormat::Text,
        }
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

// Recursively collect files from a directory
fn collect_files(path: &Path, files: &mut Vec<PathBuf>, dir_count: &mut usize) -> io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                *dir_count += 1;
                collect_files(&path, files, dir_count)?;
            } else {
                files.push(path);
            }
        }
    } else {
        files.push(path.to_path_buf());
    }
    
    Ok(())
}

// Scan a single file for credit card numbers
fn scan_file(file_path: &Path, results: &Arc<Mutex<Vec<CardMatch>>>, 
             files_with_cards: &Arc<Mutex<HashSet<String>>>, 
             skipped_files: &Arc<Mutex<Vec<String>>>) -> io::Result<()> {
    // Skip binary files or files that can't be opened as text
    match File::open(file_path) {
        Ok(file) => {
            // Try to treat as a text file
            let reader = io::BufReader::new(file);
            
            // Pattern to find potential credit card numbers with optional separators
            let card_pattern = Regex::new(r"(?:^|\D)([0-9](?:[0-9-\s]){11,18}[0-9])(?:\D|$)").unwrap();
            let file_path_str = file_path.to_string_lossy().to_string();
            let mut found_card = false;

            for (line_number, line_result) in reader.lines().enumerate() {
                match line_result {
                    Ok(line) => {
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
                                            file_path: file_path_str.clone(),
                                            line_number: line_number + 1,
                                            line_content: line.clone(),
                                        };
                                        
                                        if let Ok(mut results_vec) = results.lock() {
                                            results_vec.push(match_details);
                                        }
                                        
                                        found_card = true;
                                    }
                                }
                            }
                        }
                    },
                    Err(_) => {
                        // Line contains invalid UTF-8, might be a binary file
                        if let Ok(mut skipped) = skipped_files.lock() {
                            skipped.push(file_path_str.clone());
                        }
                        return Ok(());
                    }
                }
            }
            
            if found_card {
                if let Ok(mut files_with_cards_set) = files_with_cards.lock() {
                    files_with_cards_set.insert(file_path_str);
                }
            }
            
            Ok(())
        },
        Err(_) => {
            if let Ok(mut skipped) = skipped_files.lock() {
                skipped.push(file_path.to_string_lossy().to_string());
            }
            Ok(())
        }
    }
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
        .arg(
            Arg::with_name("format")
                .short("f")
                .long("format")
                .value_name("FORMAT")
                .help("Output format: text (default), json, csv, html, pdf")
                .takes_value(true)
                .possible_values(&["text", "json", "csv", "html", "pdf"])
                .default_value("text"),
        )
        .arg(
            Arg::with_name("no-mask")
                .long("no-mask")
                .help("Disable masking of middle digits in credit card numbers")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("summary")
                .short("s")
                .long("summary")
                .help("Generate a summary report")
                .takes_value(false),
        )
        .get_matches();

    // Check if we should show full PANs (default is to mask)
    let show_full = matches.is_present("no-mask");
    
    // Determine output format
    let format_str = matches.value_of("format").unwrap_or("text");
    let output_format = OutputFormat::from_str(format_str);
    
    // Create summary object if summary report is requested
    let generate_summary = matches.is_present("summary") || 
                          format_str == "html" || 
                          format_str == "pdf";
    
    let start_time = Instant::now();
    let summary = if generate_summary {
        Some(Arc::new(Mutex::new(ScanSummary::new())))
    } else {
        None
    };
    
    // Parse input paths
    let input_paths_str = matches.value_of("input").unwrap();
    let input_paths: Vec<&str> = input_paths_str.split(',').collect();
    
    // Collect all files to scan
    let mut files_to_scan: Vec<PathBuf> = Vec::new();
    let mut total_directories: usize = 0;
    
    for input_path in input_paths {
        let path = Path::new(input_path);
        if path.is_dir() {
            total_directories += 1;
        }
        collect_files(path, &mut files_to_scan, &mut total_directories)?;
    }
    
    if let Some(ref summary_arc) = summary {
        if let Ok(mut summary) = summary_arc.lock() {
            summary.total_files_scanned = files_to_scan.len();
            summary.total_directories_scanned = total_directories;
            
            // Add each file path to the summary
            for file_path in &files_to_scan {
                summary.add_scanned_file(&file_path.to_string_lossy());
            }
        }
    }
    
    // Calculate total size of files to scan
    let total_size: u64 = files_to_scan.iter()
        .filter_map(|path| fs::metadata(path).ok())
        .map(|meta| meta.len())
        .sum();
    
    if let Some(ref summary_arc) = summary {
        if let Ok(mut summary) = summary_arc.lock() {
            summary.total_size_scanned_mb = total_size as f64 / (1024.0 * 1024.0);
        }
    }
    
    // Thread-safe storage for results
    let results = Arc::new(Mutex::new(Vec::new()));
    
    // Set to track files with cards
    let files_with_cards = Arc::new(Mutex::new(HashSet::new()));
    
    // Set to track skipped files
    let skipped_files = Arc::new(Mutex::new(Vec::new()));
    
    // Process files in parallel
    let mut handles = vec![];
    for file_path in files_to_scan {
        let results_clone = Arc::clone(&results);
        let files_with_cards_clone = Arc::clone(&files_with_cards);
        let skipped_files_clone = Arc::clone(&skipped_files);
        let handle = thread::spawn(move || {
            if let Err(e) = scan_file(&file_path, &results_clone, &files_with_cards_clone, &skipped_files_clone) {
                eprintln!("Error scanning file {:?}: {}", file_path, e);
                if let Ok(mut skipped) = skipped_files_clone.lock() {
                    skipped.push(file_path.to_string_lossy().to_string());
                }
            }
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Update summary information if needed
    if let Some(ref summary_arc) = summary {
        if let Ok(mut summary) = summary_arc.lock() {
            if let Ok(results_vec) = results.lock() {
                summary.total_cards_found = results_vec.len();
                
                // Count card types
                for card in &*results_vec {
                    summary.increment_card_type(&card.brand);
                }
            }
            
            if let Ok(files_with_cards_set) = files_with_cards.lock() {
                summary.total_files_with_cards = files_with_cards_set.len();
                summary.clean_files = summary.total_files_scanned - summary.total_files_with_cards;
                    // Risk assessment - categorize files
                for file_path in &*files_with_cards_set {
                    // Count card occurrences per file
                    if let Ok(results_vec) = results.lock() {
                        let cards_in_file = results_vec.iter()
                            .filter(|card| card.file_path == *file_path)
                            .count();
                        
                        // Simple risk assessment
                        let risk_level = if cards_in_file > 10 {
                            "high"
                        } else if cards_in_file > 3 {
                            "medium"
                        } else {
                            "low"
                        };
                        
                        summary.add_file_by_risk(risk_level, file_path);
                    }
                }
            }
            
            if let Ok(skipped) = skipped_files.lock() {
                summary.skipped_files = skipped.clone();
            }
            
            // Record scan duration
            let duration = start_time.elapsed();
            summary.update_duration(duration);
        }
    }
    
    // Output results
    if let Some(output_path) = matches.value_of("output") {
        let output_file = File::create(output_path)?;
        let mut writer = BufWriter::new(output_file);
        
        if let Ok(results_vec) = results.lock() {
            match output_format {
                OutputFormat::Json => {
                    // Output as JSON
                    // Create a vector of sanitized results for output
                    let output_data: Vec<_> = results_vec.iter().map(|card| {
                        let mut card_output = card.clone();
                        if !show_full {
                            // Replace full PAN with masked version if masking is enabled
                            card_output.full_pan = card.masked_pan();
                            // Also mask the line content
                            card_output.line_content = card.mask_line_content();
                        }
                        card_output
                    }).collect();
                    
                    serde_json::to_writer_pretty(&mut writer, &output_data)?;
                }
                OutputFormat::Csv => {
                    // Output as CSV
                    let mut csv_writer = csv::Writer::from_writer(writer);
                    
                    // Write header
                    csv_writer.write_record(&[
                        "Brand", "PAN Length", "BIN", "Last Four", 
                        if show_full { "Full PAN" } else { "Masked PAN" },
                        "File Path", "Line Number", "Line Content"
                    ])?;
                    
                    // Write data rows
                    for card in results_vec.iter() {
                        let pan_field = if show_full { &card.full_pan } else { &card.masked_pan() };
                        
                        // Use sanitized line content if masking is enabled
                        let sanitized_line = if !show_full {
                            card.mask_line_content()
                        } else {
                            card.line_content.clone()
                        };
                        
                        csv_writer.write_record(&[
                            &card.brand,
                            &card.length.to_string(),
                            &card.bin,
                            &card.last_four,
                            pan_field,
                            &card.file_path,
                            &card.line_number.to_string(),
                            &sanitized_line
                        ])?;
                    }
                    
                    csv_writer.flush()?;
                }
                OutputFormat::Html | OutputFormat::Pdf => {
                    // Generate HTML or PDF report
                    if let Some(ref summary_arc) = summary {
                        if let Ok(summary) = summary_arc.lock() {
                            if output_format == OutputFormat::Html {
                                write!(writer, "{}", summary.to_html())?;
                            } else {
                                // For PDF, we use the same HTML but it's converted externally
                                write!(writer, "{}", summary.to_pdf_html())?;
                                
                                // Display instructions for converting HTML to PDF
                                println!("HTML file for PDF generation has been created at {}", output_path);
                                println!("To convert to PDF, use a browser or a tool like wkhtmltopdf:");
                                println!("wkhtmltopdf {} {}.pdf", output_path, output_path);
                            }
                        }
                    } else {
                        // This should not happen due to earlier conditional
                        writeln!(writer, "Summary generation was not enabled")?;
                    }
                }
                OutputFormat::Text => {
                    // Output as text (default)
                    for card_match in results_vec.iter() {
                        writeln!(writer, "{}\n", card_match.to_string(show_full))?;
                    }
                    
                    // If summary was requested, add it at the end
                    if let Some(ref summary_arc) = summary {
                        if let Ok(summary) = summary_arc.lock() {
                            writeln!(writer, "\n\n=== SUMMARY ===\n")?;
                            writeln!(writer, "Scan Date: {}", summary.scan_date)?;
                            writeln!(writer, "Scan Duration: {}", summary.scan_duration)?;
                            writeln!(writer, "Total Files Scanned: {}", summary.total_files_scanned)?;
                            writeln!(writer, "Total Directories Scanned: {}", summary.total_directories_scanned)?;
                            writeln!(writer, "Total Size Scanned: {:.2} MB", summary.total_size_scanned_mb)?;
                            writeln!(writer, "Files with Card Numbers: {}", summary.total_files_with_cards)?;
                            writeln!(writer, "Clean Files: {}", summary.clean_files)?;
                            writeln!(writer, "Total Card Numbers Found: {}", summary.total_cards_found)?;
                            
                            writeln!(writer, "\nCard Type Distribution:")?;
                            for (brand, count) in &summary.card_type_counts {
                                writeln!(writer, "  {}: {}", brand, count)?;
                            }
                            
                            // Add file list section for text output
                            writeln!(writer, "\nScanned Files:")?;
                            for file in &summary.all_scanned_files {
                                writeln!(writer, "  {}", file)?;
                            }
                        }
                    }
                }
            }
        }
        
        println!("Results written to {} in {} format", output_path, format_str);
    } else {
        // Output to console
        if let Ok(results_vec) = results.lock() {
            println!("Found {} potential credit card numbers:", results_vec.len());
            
            match output_format {
                OutputFormat::Json => {
                    // Output as JSON to console
                    // Create a vector of sanitized results for output
                    let output_data: Vec<_> = results_vec.iter().map(|card| {
                        let mut card_output = card.clone();
                        if !show_full {
                            // Replace full PAN with masked version if masking is enabled
                            card_output.full_pan = card.masked_pan();
                            // Also mask the line content
                            card_output.line_content = card.mask_line_content();
                        }
                        card_output
                    }).collect();
                    
                    println!("{}", serde_json::to_string_pretty(&output_data)?);
                }
                OutputFormat::Csv => {
                    // Output as CSV to console
                    let mut csv_writer = csv::Writer::from_writer(io::stdout());
                    
                    // Write header
                    csv_writer.write_record(&[
                        "Brand", "PAN Length", "BIN", "Last Four", 
                        if show_full { "Full PAN" } else { "Masked PAN" },
                        "File Path", "Line Number", "Line Content"
                    ])?;
                    
                    // Write data rows
                    for card in results_vec.iter() {
                        let pan_field = if show_full { &card.full_pan } else { &card.masked_pan() };
                        
                        // Use sanitized line content if masking is enabled
                        let sanitized_line = if !show_full {
                            card.mask_line_content()
                        } else {
                            card.line_content.clone()
                        };
                        
                        csv_writer.write_record(&[
                            &card.brand,
                            &card.length.to_string(),
                            &card.bin,
                            &card.last_four,
                            pan_field,
                            &card.file_path,
                            &card.line_number.to_string(),
                            &sanitized_line
                        ])?;
                    }
                    
                    csv_writer.flush()?;
                }
                OutputFormat::Html | OutputFormat::Pdf => {
                    // Cannot output HTML directly to console in a useful way
                    println!("HTML/PDF format requires an output file to be specified with -o/--output");
                    println!("Please run again with an output file path");
                }
                OutputFormat::Text => {
                    // Output as text (default)
                    for card_match in results_vec.iter() {
                        println!("{}\n", card_match.to_string(show_full));
                    }
                    
                    // If summary was requested, add it at the end
                    if let Some(ref summary_arc) = summary {
                        if let Ok(summary) = summary_arc.lock() {
                            println!("\n\n=== SUMMARY ===\n");
                            println!("Scan Date: {}", summary.scan_date);
                            println!("Scan Duration: {}", summary.scan_duration);
                            println!("Total Files Scanned: {}", summary.total_files_scanned);
                            println!("Total Directories Scanned: {}", summary.total_directories_scanned);
                            println!("Total Size Scanned: {:.2} MB", summary.total_size_scanned_mb);
                            println!("Files with Card Numbers: {}", summary.total_files_with_cards);
                            println!("Clean Files: {}", summary.clean_files);
                            println!("Total Card Numbers Found: {}", summary.total_cards_found);
                            
                            println!("\nCard Type Distribution:");
                            for (brand, count) in &summary.card_type_counts {
                                println!("  {}: {}", brand, count);
                            }
                            
                            // Display risk assessment
                            if !summary.files_by_risk["high"].is_empty() {
                                println!("\nHigh Risk Files: {}", summary.files_by_risk["high"].len());
                            }
                            if !summary.files_by_risk["medium"].is_empty() {
                                println!("Medium Risk Files: {}", summary.files_by_risk["medium"].len());
                            }
                            if !summary.files_by_risk["low"].is_empty() {
                                println!("Low Risk Files: {}", summary.files_by_risk["low"].len());
                            }
                            
                            // Calculate compliance percentage
                            let compliance_percentage = if summary.total_files_scanned > 0 {
                                (summary.clean_files as f64 / summary.total_files_scanned as f64) * 100.0
                            } else {
                                0.0
                            };
                            println!("\nCompliance Status: {:.1}% of files are free of card data", compliance_percentage);
                            
                            // Add file list section for console output
                            println!("\nScanned Files:");
                            // Limit to first 10 files to avoid flooding the console
                            let display_limit = std::cmp::min(10, summary.all_scanned_files.len());
                            for file in summary.all_scanned_files.iter().take(display_limit) {
                                println!("  {}", file);
                            }
                            if summary.all_scanned_files.len() > display_limit {
                                println!("  ... and {} more files", summary.all_scanned_files.len() - display_limit);
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}
