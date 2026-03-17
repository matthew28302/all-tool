# DNS Checker Tool

A Python command-line tool for checking DNS propagation across multiple DNS servers worldwide, similar to dnschecker.org.

## Features

✅ **No DNS Caching** - Always performs fresh queries without any caching
✅ **Multiple DNS Servers** - Query from 10 different public DNS servers globally
✅ **Multiple Record Types** - Support for A, AAAA, MX, NS, TXT, CNAME, SOA records
✅ **Propagation Detection** - Automatically detects if DNS is fully propagated
✅ **JSON Export** - Export results to JSON format for further analysis
✅ **Color-coded Output** - Easy-to-read colored terminal output
✅ **Fast & Efficient** - Parallel queries from multiple DNS servers

## Installation

### Requirements
- Python 3.7+
- pip (Python package manager)

### Setup

```bash
# Install required packages
pip install dnspython colorama

# Or use the pre-configured environment
cd /path/to/test-tool
python dns_checker.py <domain>
```

## Usage

### Basic Usage

```bash
# Check all record types for a domain
python dns_checker.py example.com

# Check specific record types
python dns_checker.py example.com A MX NS

# Check only A records
python dns_checker.py example.com A

# Check IPv6 records
python dns_checker.py example.com AAAA
```

### Examples

#### Check A and AAAA records for google.com
```bash
python dns_checker.py google.com A AAAA
```

#### Check MX records for mail.example.com
```bash
python dns_checker.py example.com MX
```

#### Check NS and SOA records
```bash
python dns_checker.py example.com NS SOA
```

## Available DNS Servers

The tool queries from the following DNS servers:

| Server Name | IP Address |
|------------|-----------|
| Google Primary | 8.8.8.8 |
| Google Secondary | 8.8.4.4 |
| Cloudflare Primary | 1.1.1.1 |
| Cloudflare Secondary | 1.0.0.1 |
| Quad9 | 9.9.9.9 |
| OpenDNS Primary | 208.67.222.222 |
| OpenDNS Secondary | 208.67.220.220 |
| Verisign | 64.6.64.6 |
| Level3 | 209.244.0.3 |
| Yandex | 77.88.8.8 |

## Supported Record Types

- **A** - IPv4 address
- **AAAA** - IPv6 address
- **MX** - Mail exchange records
- **NS** - Nameserver records
- **TXT** - Text records
- **CNAME** - Canonical name records
- **SOA** - Start of authority records

## Output Format

The tool provides:

1. **Terminal Output** - Colored, human-readable format showing results from each DNS server
2. **Summary** - Overall propagation status (fully propagated or partially propagated)
3. **Detailed JSON** - Complete results printed to console
4. **JSON Export** - Automatic export to `{domain}_dns_check.json`

### Example Output

```
Starting DNS check for example.com...

Checking A records for example.com...
  ✓ Google Primary (8.8.8.8): 104.18.26.120, 104.18.27.120
  ✓ Cloudflare Primary (1.1.1.1): 104.18.26.120, 104.18.27.120
  ✓ OpenDNS Primary (208.67.222.222): 104.18.26.120, 104.18.27.120
  ...

======================================================================
DNS Propagation Summary for example.com
Checked at: 2026-01-18T17:42:01.646363
======================================================================

✓ DNS is FULLY PROPAGATED across all checked servers
```

## Python API

You can also use the DNS Checker as a Python library:

```python
from dns_checker import DNSChecker

# Create a checker instance
checker = DNSChecker(disable_cache=True)

# Check specific record types
results = checker.check_domain('example.com', ['A', 'MX', 'NS'])

# Check propagation status
is_propagated = checker.check_propagation('example.com')
print(f"Fully propagated: {is_propagated}")

# Print summary
checker.print_summary()

# Export to JSON
checker.export_json('results.json')

# Access raw results
print(checker.results)
```

## Important Notes

### No Caching
The tool explicitly disables DNS caching at both the resolver level and query level. This ensures:
- Always fresh DNS lookups
- Accurate propagation detection
- No stale cached data from previous queries

### Propagation Detection
The tool considers DNS fully propagated when **all** DNS servers return the same set of records for a query. Since different DNS servers may return records in different orders, the tool normalizes and compares them intelligently.

### Performance
- Timeout: 5 seconds per query
- Typical check time: 1-3 seconds for all record types
- Can handle domains that don't resolve on all servers

## Troubleshooting

### "Command not found: python"
Make sure Python 3 is installed and available in your PATH.

### "ModuleNotFoundError: No module named 'dns'"
Install dnspython: `pip install dnspython`

### "DNS query timeout"
Some DNS servers may be slow or unreachable. The tool waits 5 seconds per query before timing out.

### "No records found"
If a record type doesn't exist for a domain (e.g., MX for example.com), this is expected behavior.

## Files Generated

- `{domain}_dns_check.json` - JSON export of all results

## License

MIT License - Feel free to use and modify

## Contributing

Feel free to submit improvements and bug reports!

---

**For more information about DNS:** https://en.wikipedia.org/wiki/Domain_Name_System
# all-tool
