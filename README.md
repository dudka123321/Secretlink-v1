# SecretLink

**SecretLink** is a powerful Python tool for extracting JavaScript endpoints and secrets from websites or JavaScript files.  
It supports active endpoint checking with multithreading and organizes output into structured directories for easy analysis.

## Features

- Extracts URLs and paths from JavaScript code using advanced regex patterns.
- Detects common secret tokens (API keys, tokens, passwords, etc.).
- Decodes Base64, URL-encoded, and hex-encoded strings to reveal hidden secrets.
- Checks endpoint activity (HTTP status 200) concurrently with configurable threading.
- Outputs sorted results into folders categorized by domain and content type:
  - **maindomain** vs **otherdomain**
  - **path**, **content** (images, media, documents), **static** (js, css, html)
- Organizes active endpoints similarly to extracted endpoints.
- Records which JavaScript file a secret was found in.
- Supports scanning single URLs or a list from a file.
- Customizable output directory.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/SecretLink.git
cd SecretLink
pip install -r requirements.txt
