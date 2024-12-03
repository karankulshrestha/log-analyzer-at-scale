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
def parse_log_file(log_file_path, threshold=7, num_threads=4, csv_file="log_summary.csv"):
    try:
        # Capture start time
        start_time = datetime.datetime.now()
        start_time_str = start_time.strftime("%H:%M:%S")  # Only time in hours, minutes, and seconds
        print(f"Process started at: {start_time_str}")
        
        # Regular expression to parse the log lines
        log_pattern = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<endpoint>[^ ]+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+)(?: "(?P<message>[^"]+)")?'
        )
        
        # Initialize counters and variables
        ip_request_counts = Counter()
        endpoint_counts = Counter()
        failed_ip_counts = Counter()
        total_logs = 0  # Variable to count the total logs processed

        # Read log file in chunks to process concurrently
        with open(log_file_path, 'r') as file:
            lines = file.readlines()
        
        total_logs = len(lines)  # Count total logs in the file
        
        # Divide lines into chunks for multi-threading
        chunk_size = len(lines) // num_threads
        chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
        
        # Use ThreadPoolExecutor to process chunks concurrently
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            for chunk in chunks:
                futures.append(executor.submit(process_log_chunk, chunk, ip_request_counts, endpoint_counts, failed_ip_counts, log_pattern))
            
            # Wait for all threads to complete
            for future in futures:
                future.result()

        # Find the top 10 IPs with the most requests
        top_10_ips = ip_request_counts.most_common(10)
        
        # Find the most accessed endpoint
        most_accessed_endpoint = endpoint_counts.most_common(1)[0] if endpoint_counts else ("None", 0)
        
        # Identify suspicious IPs with the highest failed login attempts
        suspicious_ips = {ip: count for ip, count in failed_ip_counts.items() if count > threshold}
        highest_failed_ip = max(suspicious_ips.items(), key=lambda x: x[1], default=("None", 0))

        # Prepare the terminal display
        console = Console()

        # Display IP Request Counts in a Table
        ip_table = Table(title="[bold green]Top 10 IPs with Highest Request Counts[/bold green]", box=box.ROUNDED)
        ip_table.add_column("IP Address", justify="center")
        ip_table.add_column("Request Count", justify="center")
        
        # Highlight the highest request IP
        for ip, count in top_10_ips:
            if count == top_10_ips[0][1]:  # The IP with the most requests
                ip_table.add_row(f"[bold yellow]{ip}[/bold yellow]", f"[bold yellow]{count}[/bold yellow]")
            else:
                ip_table.add_row(ip, str(count))
        
        console.print(ip_table)
        
        # Display the most accessed endpoint
        console.print(f"[bold yellow]Most Accessed Endpoint:[/bold yellow] {most_accessed_endpoint[0]} with {most_accessed_endpoint[1]} requests")
        
        # Display the IP with the highest failed login attempts
        console.print(f"[bold red]IP with Highest Failed Login Attempts:[/bold red] {highest_failed_ip[0]} with {highest_failed_ip[1]} failed attempts")

        # Save the data to a CSV file
        with open(csv_file, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            # Write the headers
            writer.writerow(["IP Address", "Request Count"])
            # Write the top 10 IPs
            for ip, count in top_10_ips:
                writer.writerow([ip, count])
            
            # Write the most accessed endpoint and the failed login IP
            writer.writerow([])
            writer.writerow(["Most Accessed Endpoint", most_accessed_endpoint[0], most_accessed_endpoint[1]])
            writer.writerow(["IP with Highest Failed Login Attempts", highest_failed_ip[0], highest_failed_ip[1]])

        # Capture finish time
        finish_time = datetime.datetime.now()
        finish_time_str = finish_time.strftime("%H:%M:%S")  # Only time in hours, minutes, and seconds
        print(f"Process finished at: {finish_time_str}")
        print(f"Total time taken: {finish_time - start_time}")
        print(f"Total number of logs processed: {total_logs}")
        
        console.print(f"[bold green]Log summary has been saved to {csv_file}.[/bold green]")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")

# Call the function
log_file_path = "sample.log"
parse_log_file(log_file_path)
