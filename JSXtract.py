#!/usr/bin/env python3
import re
import requests
import argparse
import sys
import json
import csv
import tldextract
import concurrent.futures
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from rich import print
from rich.console import Console
from rich.table import Table
import math

def extract_js_links(domain):
    """Extract JavaScript files from a given domain."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(f"https://{domain}", headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        js_links = {urljoin(f"https://{domain}", script['src']) for script in scripts}
        return js_links
    except requests.RequestException as e:
        print(f"[red]Error fetching JS links from {domain}: {e}[/red]")
        return set()

def extract_subdomains(js_content, domain):
    extracted = tldextract.extract(domain)
    root_domain = f"{extracted.domain}.{extracted.suffix}"
    subdomain_pattern = rf"https?://([a-zA-Z0-9.-]+\\.{re.escape(root_domain)})"
    return set(re.findall(subdomain_pattern, js_content))

def extract_endpoints(js_content, domain):
    endpoint_pattern = rf"https?://{re.escape(domain)}/[a-zA-Z0-9/_-]+"
    relative_pattern = r"['\"](/[^'\"]+)['\"]"
    return set(re.findall(endpoint_pattern, js_content)) | set(re.findall(relative_pattern, js_content))

def entropy(string):
    """Calculate Shannon entropy to detect API keys more accurately."""
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    return -sum([p * math.log2(p) for p in prob])

def extract_api_keys(js_content):
    api_key_patterns = [
        r'(?i)(?:api_key|apikey|key|token|access_token)[\s:="\' ]*([A-Za-z0-9-_]{10,})',

        r"(?:aws_access_key_id|aws_secret_access_key)[\s:=\"']*([A-Za-z0-9+/=]{16,40})",
    ]
    found_keys = set()
    for pattern in api_key_patterns:
        found_keys.update(re.findall(pattern, js_content))
    return {key for key in found_keys if entropy(key) > 3.5}  # Reduce false positives

def fetch_js_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"[red]Error fetching {url}: {e}[/red]")
        return None

def analyze_js_content(js_content, domain, include_api):
    subdomains = extract_subdomains(js_content, domain)
    endpoints = extract_endpoints(js_content, domain)
    api_keys = extract_api_keys(js_content) if include_api else set()
    return subdomains, endpoints, api_keys

def save_results(results, output_format):
    if output_format == "json":
        with open("results.json", "w") as f:
            json.dump(results, f, indent=4)
    elif output_format == "csv":
        with open("results.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Value"])
            for category, items in results.items():
                for item in items:
                    writer.writerow([category, item])

def main():
    parser = argparse.ArgumentParser(description="Extract subdomains, endpoints, and API keys from JS files.")
    parser.add_argument("--file", help="Analyze a local JavaScript file.")
    parser.add_argument("--urls", nargs='+', help="List of JS file URLs to analyze.")
    parser.add_argument("--domains", nargs='+', help="List of domains to extract JS files from.")
    parser.add_argument("--api", action='store_true', help="Include API key extraction.")
    parser.add_argument("--output", choices=["json", "csv"], help="Save results in JSON or CSV format.")
    args = parser.parse_args()
    
    urls = []
    
    if not sys.stdin.isatty():  # Check if input is piped
        urls = [line.strip() for line in sys.stdin if line.strip()]
    
    if args.urls:
        urls.extend(args.urls)
    
    if args.domains:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_domain = {executor.submit(extract_js_links, domain): domain for domain in args.domains}
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    js_links = future.result()
                    urls.extend(js_links)
                except Exception as e:
                    print(f"[red]Error extracting JS from {domain}: {e}[/red]")
    
    if not args.file and not urls:
        print("[yellow]Please provide --file, --urls, --domains (or pipe URLs via stdin).[/yellow]")
        return
    
    js_content = ""
    domain = ""
    console = Console()
    
    results = {"subdomains": set(), "endpoints": set(), "api_keys": set()}
    
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                js_content = f.read()
            domain = "local_file"
            subdomains, endpoints, api_keys = analyze_js_content(js_content, domain, args.api)
            results["subdomains"].update(subdomains)
            results["endpoints"].update(endpoints)
            results["api_keys"].update(api_keys)
        except Exception as e:
            print(f"[red]Error reading file: {e}[/red]")
            return
    
    if urls:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_url = {executor.submit(fetch_js_content, url): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    js_content = future.result()
                    if js_content:
                        domain = urlparse(url).netloc
                        subdomains, endpoints, api_keys = analyze_js_content(js_content, domain, args.api)
                        results["subdomains"].update(subdomains)
                        results["endpoints"].update(endpoints)
                        results["api_keys"].update(api_keys)
                except Exception as e:
                    print(f"[red]Error processing {url}: {e}[/red]")
    
    table = Table(title="Extracted Data")
    table.add_column("Category", style="bold cyan")
    table.add_column("Values", style="bold white")
    
    for category, items in results.items():
        table.add_row(category, "\n".join(items) if items else "None")
    
    console.print(table)
    
    if args.output:
        save_results(results, args.output)
        print(f"[green]Results saved in results.{args.output}[/green]")
    
if __name__ == "__main__":
    main()

