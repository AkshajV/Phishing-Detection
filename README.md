# Email URL Checker

A Python tool that analyzes email files (.eml) to extract and check URLs against PhishTank's database for potential phishing attempts.

## Features

- Parses .eml files to extract:
  - Sender information
  - Email subject
  - Email body
  - URLs from both plain text and HTML content
- Checks URLs against PhishTank's database
- Supports URL whitelisting
- Handles various email encodings and formats

## Requirements

- Python 3.x
- Required packages (install via `pip install -r requirements.txt`):
  - beautifulsoup4
  - requests
  - urlextract

## Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create an `emails` directory and place your .eml files there
4. Configure your whitelist in `whitelist.json`
5. (Optional) Add your PhishTank API key in `email_checker.py`

## Usage

Run the script:
```bash
python email_checker.py
```

The script will:
1. Process all .eml files in the `emails` directory
2. Extract URLs from each email
3. Check each URL against PhishTank's database
4. Display results for each URL found

## Configuration

- `whitelist.json`: Configure trusted domains and URLs
- `email_checker.py`: Add your PhishTank API key if you have one

## License

MIT License 