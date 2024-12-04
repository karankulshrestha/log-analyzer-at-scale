import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich import box
import csv
import datetime

# Function to process a chunk of the log file
def process_log_chunk(chunk, ip_request_counts, endpoint_counts, failed_ip_counts, log_pattern):
    for line in chunk:
        match = log_pattern.match(line.strip())
        if match:
            log_data = match.groupdict()
            ip = log_data['ip']
            endpoint = log_data['endpoint']
            status = int(log_data['status'])
            message = log_data.get('message', '')
            
            # Count IP requests
            ip_request_counts[ip] += 1
            
            # Count endpoint accesses
            endpoint_counts[endpoint] += 1
            
            # Count failed login attempts (401 status)
            if status == 401 or message == "Invalid credentials":
                failed_ip_counts[ip] += 1

# Function to process the log file with threading
def parse_log_file(log_file_path, threshold=10, num_threads=4, csv_file="log_summary.csv"):
    try:
        # Prompt user for threshold if not provided
        user_input = input(f"Enter the threshold for suspicious activity detection (default: {threshold}): ")
        if user_input.strip().isdigit():
            threshold = int(user_input.strip())
        
        # Capture start time
        start_time = datetime.datetime.now()
        start_time_str = start_time.strftime("%H:%M:%S")
        print(f"Process started at: {start_time_str}")
        
        # Regular expression to parse the log lines
        log_pattern = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<endpoint>[^ ]+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+)(?: "(?P<message>[^"]+)")?'
        )
        
        # Initialize counters
        ip_request_counts = Counter()
        endpoint_counts = Counter()
        failed_ip_counts = Counter()
        total_logs = 0

        # Read log file
        with open(log_file_path, 'r') as file:
            lines = file.readlines()
        
        total_logs = len(lines)
        chunk_size = len(lines) // num_threads
        chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
        
        # Process logs concurrently
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            for chunk in chunks:
                futures.append(executor.submit(process_log_chunk, chunk, ip_request_counts, endpoint_counts, failed_ip_counts, log_pattern))
            for future in futures:
                future.result()

        # Top 10 IPs with most requests
        top_10_ips = ip_request_counts.most_common(10)
        most_accessed_endpoint = endpoint_counts.most_common(1)[0] if endpoint_counts else ("None", 0)
        suspicious_ips = {ip: count for ip, count in failed_ip_counts.items() if count > threshold}
        top_10_suspicious_ips = Counter(suspicious_ips).most_common(10)

        # Prepare display
        console = Console()

        # Display top 10 IPs
        ip_table = Table(title="[bold green]Top 10 IPs with Highest Request Counts[/bold green]", box=box.ROUNDED)
        ip_table.add_column("IP Address", justify="center")
        ip_table.add_column("Request Count", justify="center")
        for ip, count in top_10_ips:
            ip_table.add_row(ip, str(count))
        console.print(ip_table)

        # Display most accessed endpoint
        console.print(
            f"[bold cyan]Most Frequently Accessed Endpoint:[/bold cyan] {most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)"
        )

        # Display suspicious IPs
        suspicious_table = Table(title="[bold red]Top 10 Suspicious Activities Detected[/bold red]", box=box.ROUNDED)
        suspicious_table.add_column("IP Address", justify="center")
        suspicious_table.add_column("Failed Login Attempts", justify="center")
        for ip, count in top_10_suspicious_ips:
            suspicious_table.add_row(ip, str(count))
        console.print(suspicious_table)

        # Save data to CSV
        with open(csv_file, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in top_10_ips:
                writer.writerow([ip, count])
            writer.writerow([])
            writer.writerow(["Most Accessed Endpoint", most_accessed_endpoint[0], most_accessed_endpoint[1]])
            writer.writerow(["Top 10 Suspicious IPs"])
            for ip, count in top_10_suspicious_ips:
                writer.writerow([ip, count])

        finish_time = datetime.datetime.now()
        finish_time_str = finish_time.strftime("%H:%M:%S")
        print(f"Process finished at: {finish_time_str}")
        print(f"Total time taken: {finish_time - start_time}")
        print(f"Total number of logs processed: {total_logs}")
        console.print(f"[bold green]Log summary has been saved to {csv_file}.[/bold green]")

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")

# Call the function
log_file_path = "sample.log"
parse_log_file(log_file_path)
