COMP H2702 - IP Reputation Project Resources

Purpose
This package supports a reproducible IP-reputation project while still allowing students to demonstrate a real API request.

Files
- suspicious_ips.txt: synthetic documentation-range IPs used for the main batch analysis. Do not scan or contact these addresses.
- mock_reputation_data.json: synthetic API-like reputation data for the same IPs. This makes the main project reproducible for every student.
- approved_live_test_ips.txt: well-known public DNS resolver IPs that may be used ONLY to test an AbuseIPDB CHECK request. Reputation results can change and are not part of the fixed answer key.

Minimum project expectation
1. Read suspicious_ips.txt.
2. Read and parse mock_reputation_data.json.
3. Print/report confidence score, country and whitelist status for every supplied synthetic IP.
4. Apply and explain a simple risk classification of your own design.
5. Demonstrate at least one real API request to an approved_live_test_ips.txt address using an API key stored outside the source code. If the external service is unavailable during marking, show clear error handling and retain evidence of a previous successful run.

Security
Never commit API keys to GitHub. Do not scan or connect to the supplied IP addresses. This project performs reputation lookups only.
