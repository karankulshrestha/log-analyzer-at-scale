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
    size = random.randint(100, 2000)
    message = random.choice(messages) if status == 401 else ""
    
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

# Function to generate log entries for multiple requests from the same IP
def generate_logs_for_ip(ip, num_requests):
    return [generate_log_entry(ip) for _ in range(num_requests)]

# Generate a list of IPs with random request counts
log_entries = []
ip_request_counts = [18, 9, 12, 11, 1]  # List of random request counts for each IP

for _ in range(100000):  # Generate logs for 100 different IPs
    ip = fake.ipv4()  # Generate a random IP address
    num_requests = random.choice(ip_request_counts)  # Randomly select the number of requests for this IP
    log_entries.extend(generate_logs_for_ip(ip, num_requests))  # Generate the logs and add to the list

# Save to a log file
with open("sample.log", "w") as file:
    for entry in log_entries:
        file.write(entry + "\n")

print("Log entries have been generated and saved to 'sample.log'.")
