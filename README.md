SecretLink
SecretLink is a powerful Python tool for extracting JavaScript endpoints and secrets from websites or JavaScript files. It supports active endpoint checking with multithreading and organizes output into structured directories for easy analysis.

Features
Extracts URLs and paths from JavaScript code using advanced regex patterns.

Detects common secret tokens (API keys, tokens, passwords, etc.).

Decodes Base64, URL-encoded, and hex-encoded strings to reveal hidden secrets.

Checks endpoint activity (HTTP status 200) concurrently with configurable threading.

Outputs sorted results into folders categorized by domain and content type:

maindomain vs otherdomain

path, content (images, media, documents), static (js, css, html)

Organizes active endpoints similarly to extracted endpoints.

Records which JavaScript file a secret was found in.

Supports scanning single URLs or a list from a file.

Customizable output directory.

Installation
Clone the repository:

bash
Копировать
Редактировать
git clone https://github.com/yourusername/SecretLink.git
cd SecretLink
Create a virtual environment and activate it (optional but recommended):

bash
Копировать
Редактировать
python3 -m venv venv
source venv/bin/activate
Install dependencies:

bash
Копировать
Редактировать
pip install -r requirements.txt
Usage
bash
Копировать
Редактировать
python Secretlink-v1.py [options]
Options
-u, --url — Single URL to scan.

-l, --list — File containing a list of URLs to scan.

-b, --base — Base URL to resolve relative paths.

-a, --active — Check endpoints for activity (HTTP 200 status).

-o, --output-dir — Directory to save output (creates subfolders).

-t, --threads — Number of threads for active checking (default: 10).

Examples
Scan a single URL and check active endpoints with 20 threads:

bash
Копировать
Редактировать
python Secretlink-v1.py -u https://example.com -a -t 20 -o ./results
Scan multiple URLs from a file:

bash
Копировать
Редактировать
python Secretlink-v1.py -l urls.txt -o ./output
Output Structure
Results are saved in the specified output directory, organized as follows:

pgsql
Копировать
Редактировать
output-dir/
├── endpoints/
│   ├── maindomain/
│   │   ├── path/
│   │   ├── content/
│   │   └── static/
│   └── otherdomain/
│       ├── path/
│       ├── content/
│       └── static/
├── active/ (only if -a is used)
│   ├── maindomain/
│   │   ├── path/
│   │   ├── content/
│   │   └── static/
│   └── otherdomain/
│       ├── path/
│       ├── content/
│       └── static/
└── secrets/
    └── secrets.txt  (includes filename info where secrets were found)
Dependencies
Python 3.7+

requests

tldextract

Install dependencies with:

bash
Копировать
Редактировать
pip install -r requirements.txt
Notes
The tool uses tldextract to correctly classify domains and separate main domain endpoints from third-party services.

Active endpoint checking uses multithreading for speed.

Secrets are matched by common keywords and decoded from common encodings.

Output files are appended for each run.

License
This project is licensed under the MIT License.
