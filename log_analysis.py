# File: log_analysis_class.py

import re
import csv
from collections import Counter, defaultdict


class LogAnalyzer:
    """
    A class to analyze server log files for various metrics including:
    - Request counts per IP address
    - Most accessed endpoint
    - Suspicious activity (failed login attempts)

    Attributes:
        log_file (str): Path to the input log file.
        output_csv (str): Path to the output CSV file for results.
        suspicious_threshold (int): Threshold for flagging suspicious activity.
        failed_status_code (str): HTTP status code indicating failed login attempts.
    """

    def __init__(self, log_file, output_csv, suspicious_threshold=10, failed_status_code="401"):
        """
        Initializes the LogAnalyzer with the log file and configuration.

        Args:
            log_file (str): Path to the log file to analyze.
            output_csv (str): Path to the output CSV file.
            suspicious_threshold (int): Threshold for flagging suspicious activity.
            failed_status_code (str): HTTP status code indicating failed login attempts.
        """
        self.log_file = log_file
        self.output_csv = output_csv
        self.suspicious_threshold = suspicious_threshold
        self.failed_status_code = failed_status_code
        self.ip_requests = Counter()
        self.endpoint_requests = Counter()
        self.failed_logins = defaultdict(int)

    def parse_logs(self):
        """
        Parses the log file to extract relevant data:
        - Counts requests per IP address.
        - Counts requests per endpoint.
        - Tracks failed login attempts.
        """
        log_pattern = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?P<method>[A-Z]+) (?P<endpoint>.*?) HTTP/.*?" (?P<status>\d+) .*'
        )

        try:
            with open(self.log_file, 'r') as file:
                for line in file:
                    match = log_pattern.match(line)
                    if match:
                        ip = match.group('ip')
                        endpoint = match.group('endpoint')
                        status = match.group('status')

                        # Update counts for IP addresses and endpoints
                        self.ip_requests[ip] += 1
                        self.endpoint_requests[endpoint] += 1

                        # Track failed login attempts
                        if status == self.failed_status_code:
                            self.failed_logins[ip] += 1
        except FileNotFoundError:
            print(f"Error: File {self.log_file} not found.")
            raise
        except Exception as e:
            print(f"An unexpected error occurred while reading the log file: {e}")
            raise

    def get_sorted_ip_requests(self):
        """
        Returns:
            list: A sorted list of tuples with IP addresses and request counts.
        """
        return self.ip_requests.most_common()

    def get_most_accessed_endpoint(self):
        """
        Returns:
            tuple: The most accessed endpoint and its count, or (None, 0) if no data exists.
        """
        if self.endpoint_requests:
            return self.endpoint_requests.most_common(1)[0]
        return None, 0

    def get_suspicious_activity(self):
        """
        Identifies IP addresses with failed login attempts exceeding the threshold.

        Returns:
            dict: IP addresses as keys and failed login counts as values.
        """
        return {ip: count for ip, count in self.failed_logins.items() if count > self.suspicious_threshold}

    def save_results_to_csv(self):
        """
        Saves analysis results to the specified CSV file in a structured format.
        """
        try:
            with open(self.output_csv, mode='w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile)

                # Write IP request counts
                csv_writer.writerow(["Requests per IP"])
                csv_writer.writerow(["IP Address", "Request Count"])
                csv_writer.writerows(self.get_sorted_ip_requests())

                # Write the most accessed endpoint
                csv_writer.writerow([])
                csv_writer.writerow(["Most Accessed Endpoint"])
                csv_writer.writerow(["Endpoint", "Access Count"])
                most_accessed = self.get_most_accessed_endpoint()
                csv_writer.writerow(most_accessed)

                # Write suspicious activity
                csv_writer.writerow([])
                csv_writer.writerow(["Suspicious Activity"])
                csv_writer.writerow(["IP Address", "Failed Login Count"])
                csv_writer.writerows(self.get_suspicious_activity().items())

            print(f"Results saved to {self.output_csv}")
        except IOError:
            print(f"Error: Unable to write to {self.output_csv}")
            raise

    def display_results(self):
        """
        Displays analysis results in a human-readable format in the terminal.
        """
        print("\nIP Address Request Counts:")
        print(f"{'IP Address':<20} {'Request Count':<15}")
        for ip, count in self.get_sorted_ip_requests():
            print(f"{ip:<20} {count:<15}")

        print("\nMost Frequently Accessed Endpoint:")
        endpoint, count = self.get_most_accessed_endpoint()
        print(f"{endpoint} (Accessed {count} times)")

        print("\nSuspicious Activity Detected:")
        suspicious_activity = self.get_suspicious_activity()
        if suspicious_activity:
            print(f"{'IP Address':<20} {'Failed Login Attempts':<25}")
            for ip, count in suspicious_activity.items():
                print(f"{ip:<20} {count:<25}")
        else:
            print("No suspicious activity detected.")

    def run_analysis(self):
        """
        Executes the full log analysis workflow:
        - Parses the log file.
        - Displays results in the terminal.
        - Saves results to a CSV file.
        """
        self.parse_logs()
        self.display_results()
        self.save_results_to_csv()


def main():
    """
    Main entry point for the script. Configures the LogAnalyzer and runs the analysis.
    """
    log_file = "sample.log"  # Input log file
    output_csv = "log_analysis_results.csv"  # Output CSV file

    try:
        analyzer = LogAnalyzer(log_file, output_csv)
        analyzer.run_analysis()
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
