# Security POC (Proof of Concepts)

This repository is dedicated to various security proof of concepts to illustrate specific tests or security queries. It's a compilation of libraries, references, and examples to assist in understanding and demonstrating certain security scenarios. 

> :warning: **Note**: This repo is for demonstration and learning purposes. It does not contain any secrets or sensitive information. 

Each folder generally represents a distinct proof of concept or test scenario.

## Usage

1. Navigate to the desired test or PoC folder.
2. Each folder contains:
   - A brief `README.md` explaining the concept or test.
   - Scripts or configuration files relevant to the test.  These are numbered to show the order in which they get executed.
   - A `99_cleanup.sh` script to revert any configurations or changes made during the demonstration.

## haveibeenpwned_domain_report Tool

The Have I Been Pwned Domain Report Tool is a straightforward command-line utility that interacts with the HIBP API to generate a report on email breaches for a specified domain. Users with an HIBP account can use this tool to extract information about compromised emails linked to their domain and analyze the breaches in detail. The tool outputs a CSV file that lists breached emails, categorizes the types of data exposed (like passwords or phone numbers), and provides the dates of these breaches.

**Usage**: Execute `tools/haveibeenpwned_domain_report example.com | tee ~/Downloads/$(date +%Y-%m-%d)_hibp-example.com.csv` in the terminal. Replace `example.com` with the domain you're investigating.

**Output Columns**:
- **Email**: The breached email addresses under the domain.
- **Data Types**: Separate columns for each type of compromised data, filled with breach dates. If an email has no data breached of a specific type, that cell is left empty.
- **Breaches**: Lists the names of breaches an email was involved in, separated by commas.

**Example Entry in CSV**:
```
Email, Passwords, Phone Numbers, Usernames, IP Addresses, Breaches
jane@example.com, "2024-01-23", "", "2024-01-23, 2019-04-01", "", "BreachName1, BreachName2"
```
This line indicates that `jane@example.com` had her passwords exposed in a breach on January 23, 2024, and her usernames were exposed in two breaches on January 23, 2024, and April 1, 2019. The `Breaches` column lists the names of the breaches she was involved in.