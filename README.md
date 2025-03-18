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
```

##📌 Usage
1️⃣ Extract from JavaScript file URLs
```sh
cat list_of_JSurls.txt | python jsxtract.py --domains | anew domains.txt
```

##📌 Basic Usage
```sh
python jsxtract.py --urls https://example.com/main.js
```

2️⃣ Extract JavaScript from domains
```sh
python jsxtract.py --domains example.com
```

3️⃣ Analyze a local JavaScript file
```sh
python jsxtract.py --file sample.js
```

4️⃣ Extract API keys along with subdomains & endpoints
```sh
python jsxtract.py --urls https://example.com/script.js --api
```

5️⃣ Save results in JSON or CSV
```sh
python jsxtract.py --urls https://example.com/script.js --output json
python jsxtract.py --urls https://example.com/script.js --output csv
```
🛠️ To-Do / Future Improvements
- Add more API key patterns
- Improve regex for endpoint detection
- Implement better error handling


