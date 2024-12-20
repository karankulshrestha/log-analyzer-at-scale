
# Scalable Web Log Analysis Using Multithreading

This script analyzes web server logs efficiently using multithreading, enabling fast processing of large log file. It provides key insights like top IPs, most accessed endpoints, and failed login attempts, making it ideal for web requests analysis and identifying potential security issues.




## Testing on the given log file

![s2](https://github.com/user-attachments/assets/ff023e54-5fa3-43e2-9303-9e68f5329518)

- Above logs analysis displays top highest requests count along with most accessed endpoint and ip with highest login attempts at `specific threshold`.

![s3](https://github.com/user-attachments/assets/6e410244-f5f6-40e1-afbb-b60bade320fb)

- Above logs analysis stored in `CSV File`





## Testing the Script at Scale

1. **Generate Sample Log**:  
   Use the `generate.py` script to create a `sample.log` file. Set the desired number of entries (e.g., `100,000` or `200,000`) for testing.

2. **Run the Analyzer**:  
   Execute `main.py` with the generated `sample.log` as input.

3. **Measure Performance**:  
   - Note the execution time.  
   - Review results displayed in the terminal and stored in the `log_summary.csv` file.  

This process validates the script's efficiency and scalability.

    
## Screenshots

![s1](https://github.com/user-attachments/assets/89cea66d-5eba-403a-8774-0225d53063e0)


- Total logs processed in the above are (`10,00,000`)

![s2](https://github.com/user-attachments/assets/fb18fdf7-065e-47c6-8a83-69901141d09e)

- Above logs generated using (`generate.py`)
