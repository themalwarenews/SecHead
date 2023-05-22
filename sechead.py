import argparse
import requests
from termcolor import colored
from urllib.parse import urlparse
from prettytable import PrettyTable

# Best practice security headers
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces secure (HTTP over SSL/TLS) connections to the server.",
    "Content-Security-Policy": "Helps prevent cross-site scripting (XSS) and other code injection attacks.",
    "X-Content-Type-Options": "Prevents MIME type sniffing.",
    "X-Frame-Options": "Protects against clickjacking.",
    "X-XSS-Protection": "Protects against XSS attacks.",
    "Referrer-Policy": "Controls how much referrer information should be included with requests.",
    "Permissions-Policy": "Controls which browser features can be used by the site.",
}

def analyze_security_headers(url):
    response = requests.get(url)
    headers = response.headers

    used_headers = {}
    missing_headers = {}

    for header, description in SECURITY_HEADERS.items():
        if header in headers:
            used_headers[header] = description
        else:
            missing_headers[header] = description

    return used_headers, missing_headers

def print_headers(headers, color):
    table = PrettyTable(["Header", "Description"])
    for header, description in headers.items():
        table.add_row([colored(header, color), description])
    print(table)

def get_grade(used_headers):
    num_headers = len(SECURITY_HEADERS)
    num_used_headers = len(used_headers)

    if num_used_headers == num_headers:
        return "A+"
    elif num_used_headers >= num_headers * 0.9:
        return "A"
    elif num_used_headers >= num_headers * 0.8:
        return "B"
    elif num_used_headers >= num_headers * 0.7:
        return "C"
    elif num_used_headers >= num_headers * 0.6:
        return "D"
    else:
        return "F"

def process_url(url):
    # Check if the URL has a scheme (e.g. "https://")
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        # If not, add "https://" to the beginning of the URL
        url = "https://" + url

    try:
        used_headers, missing_headers = analyze_security_headers(url)

        print("\nDomain:", url)
        print("\nUsed security headers:")
        print_headers(used_headers, "green")

        print("\nMissing security headers:")
        print_headers(missing_headers, "red")

        grade = get_grade(used_headers)
        print("\n\n")
        print("\t\t\t+---------------------+-----------------------+")
        print(colored(f"\t\t\t\tThe Grade of website is : {grade}","blue"))
        print("\t\t\t+---------------------+-----------------------+")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', type=str, help='Single domain to analyze')
    parser.add_argument('-f', '--file', type=str, help='File with a list of domains to analyze')
    args = parser.parse_args()

    print(colored("""
  ____  __________   ____         ____    _____________        _     ________   
 6MMMMb\`MMMMMMMMM  6MMMMb/       `MM'    `MM`MMMMMMMMM       dM.    `MMMMMMMb. 
6M'    ` MM      \ 8P    YM        MM      MM MM      \      ,MMb     MM    `Mb 
MM       MM       6M      Y        MM      MM MM             d'YM.    MM     MM 
YM.      MM    ,  MM               MM      MM MM    ,       ,P `Mb    MM     MM 
 YMMMMb  MMMMMMM  MM               MMMMMMMMMM MMMMMMM       d'  YM.   MM     MM 
     `Mb MM    `  MM               MM      MM MM    `      ,P   `Mb   MM     MM 
      MM MM       MM               MM      MM MM           d'    YM.  MM     MM 
      MM MM       YM      6        MM      MM MM          ,MMMMMMMMb  MM     MM 
L    ,M9 MM      / 8b    d9        MM      MM MM      /   d'      YM. MM    .M9 
MYMMMM9 _MMMMMMMMM  YMMMM9        _MM_    _MM_MMMMMMMMM _dM_     _dMM_MMMMMMM9' 
                                                                                
                                                    
""", "green"))
    if args.domain:
        process_url(args.domain)
    elif args.file:
        with open(args.file) as file:
            for line in file:
                process_url(line.strip())
                print(colored("\n" + "="*120 + "\n","cyan"))  # Separator line

if __name__ == "__main__":
    main()
