# JSXtract 🕵️‍♂️🔍

JSXtract is a powerful tool for extracting **subdomains, endpoints, and API keys** from JavaScript files.  
It can **fetch JavaScript files from a list of domains**, analyze them, and uncover hidden assets, making it an essential tool for **bug bounty hunters and penetration testers**.

## Features ✨
- **Subdomain Extraction** – Finds subdomains related to a target domain.  
- **Endpoint Discovery** – Extracts API endpoints from JavaScript files.  
- **API Key Detection** – Identifies API keys using entropy-based filtering.  
- **JS File Collection** – Fetches JavaScript files from homepages of given domains.  
- **Multi-threaded** – Fast and efficient scanning.  
- **File & URL Support** – Can analyze local JavaScript files or fetch them from provided URLs.  
- **Piped Input Support** – Works with tools like `gau`.  

## Installation 🛠️
Ensure you have **Python 3.7+** installed.

```sh
git clone https://github.com/yourusername/JSXtract.git
cd JSXtract
pip install -r requirements.txt
