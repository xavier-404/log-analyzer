# Log Analysis Script Documentation

## Objective

The goal of this script is to analyze server log files for various metrics to identify trends, detect potential threats, and generate a detailed report. It encapsulates the analysis logic in a modular, class-based design for maintainability and extensibility.

---

## Modular Design

The script is encapsulated in a **`LogAnalyzer` class**, with each analysis task defined as a method. It supports configuration for detecting suspicious activity and ensures clear separation of concerns.

---

## Key Features

### 1. Parsing Strategy

- **Regex-Based Parsing**: 
  - The script uses a robust regex to extract relevant fields from each log entry, including:
    - IP address
    - HTTP method
    - Requested endpoint
    - Status code
  - This approach supports variations in log formats.

- **Data Handling**:
  - Uses `Counter` and `defaultdict` for efficient aggregation and analysis.

---

### 2. Analysis Methods

- **`parse_logs()`**:
  - Reads the log file line by line, applying regex to extract required data fields.
  - Updates:
    - Request counts per IP
    - Endpoint access counts
    - Failed login attempts for IPs

- **`get_sorted_ip_requests()`**:
  - Returns a sorted list of IP addresses and their respective request counts in descending order.
  
- **`get_most_accessed_endpoint()`**:
  - Identifies and returns the most accessed endpoint along with its count.

- **`get_suspicious_activity()`**:
  - Flags IPs with failed login attempts exceeding a configurable threshold (`suspicious_threshold`).
  - Returns a dictionary of flagged IPs and their failed attempt counts.

---

### 3. Output Methods

- **`display_results()`**:
  - Prints the analysis results in a well-organized, human-readable format:
    - Request counts by IP
    - Most accessed endpoint
    - Detected suspicious activity

- **`save_results_to_csv()`**:
  - Saves the results to a structured CSV file:
    - Requests per IP
    - Most accessed endpoint
    - Suspicious activity data
  - Ensures compatibility with spreadsheet tools for further analysis.

---

## Flexibility

### Configuration Options

- Allows customization of:
  - **`suspicious_threshold`**: Number of failed login attempts to flag as suspicious.
  - **`failed_status_code`**: HTTP status code for failed login attempts (default: `401`).

### Scalability

- Designed to handle small-to-medium log files efficiently with a single-pass log parsing mechanism.
- Easily extendable for handling large files or distributed log storage.

### Adaptability

- The regex pattern can be modified to support alternate log formats.
- Supports different output file types (can be extended to JSON or database).

---

## How to Use

1. **Setup**:
   - Save the script as `log_analysis.py`.
   - Place the `sample.log` file in the same directory.

2. **Run the Script**:
   ```bash
   python log_analysis.py
