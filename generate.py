import random
from faker import Faker
import datetime

fake = Faker()

# Sample log entry template
log_template = "{ip} - - [{timestamp}] \"{method} {endpoint} HTTP/1.1\" {status} {size} {message}"

# Methods, status codes, and sample log messages
methods = ["GET", "POST"]
status_codes = [200, 401, 404, 500]
endpoints = ["/home", "/about", "/contact", "/login", "/register", "/profile", "/dashboard", "/feedback"]
messages = ["Invalid credentials", "User created successfully", "Page not found", "Server error"]

# Function to generate a single log entry
def generate_log_entry(ip):
    timestamp = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    method = random.choice(methods)
    endpoint = random.choice(endpoints)
    status = random.choice(status_codes)
    
    # Assign "Invalid credentials" only for 401 status
    message = "Invalid credentials" if status == 401 else random.choice(messages) if status != 200 else ""
    
    size = random.randint(100, 2000)
    log_entry = log_template.format(
        ip=ip,
        timestamp=timestamp,
        method=method,
        endpoint=endpoint,
        status=status,
        size=size,
        message=f'"{message}"' if message else ""
    )
    return log_entry

# Function to generate logs for a single IP with random request counts
def generate_logs_for_ip(ip, max_requests):
    num_requests = random.randint(1, max_requests)
    logs = []
    for _ in range(num_requests):
        logs.append(generate_log_entry(ip))
    return logs

# Main function to generate the specified number of log entries
def generate_log_file():
    try:
        # Prompt user for number of log entries
        total_entries = int(input("Enter the total number of log entries to generate: ").strip())
        max_requests_per_ip = 25  # Maximum number of requests per IP
        
        log_entries = []
        while len(log_entries) < total_entries:
            ip = fake.ipv4()  # Generate a random IP address
            logs = generate_logs_for_ip(ip, max_requests_per_ip)
            log_entries.extend(logs)
        
        # Trim the list to match the exact number of requested entries
        log_entries = log_entries[:total_entries]
        
        # Save logs to a file
        with open("sample.log", "w") as file:
            for entry in log_entries:
                file.write(entry + "\n")
        
        print(f"{total_entries} log entries have been generated and saved to 'sample.log'.")
    except ValueError:
        print("Invalid input. Please enter a valid number.")

# Call the function to generate the log file
generate_log_file()
