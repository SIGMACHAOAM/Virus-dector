import re
import os
import chardet
import pefile
import webbrowser

# ANSI color codes
GREEN = "\033[1;32m"
RED = "\033[1;31m"
WHITE = "\033[1;37m"
RESET = "\033[0m"

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Prints the scanner's header with styling."""
    print(WHITE)
    print("=" * 50)
    print("  Advanced File Scanner - Discord & Malware Detection")
    print("=" * 50)

def detect_file_type(file_path):
    """Returns the file extension."""
    return os.path.splitext(file_path)[-1].lower()

def scan_exe_file(file_path):
    """Scans EXE files for suspicious behavior."""
    print("\nScanning EXE file for malware...\n")

    try:
        pe = pefile.PE(file_path)

        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
            print(GREEN + "✔ EXE is digitally signed (likely safe)." + RESET)
        else:
            print(RED + "✖ EXE is NOT digitally signed (could be malicious)." + RESET)

        with open(file_path, 'rb') as file:
            raw_data = file.read()

        packer_patterns = [b"UPX", b"MPRESS", b"ASPack"]
        if any(pattern in raw_data for pattern in packer_patterns):
            print(RED + "✖ This EXE appears to be packed (used to hide malware)." + RESET)

    except Exception as e:
        print(f"Error scanning EXE: {e}")

def scan_file(file_path):
    """Scans the file for Discord Webhooks, App IDs, and malware indicators."""
    clear_screen()
    print_header()

    print("\nScanning file for threats...\n")

    file_extension = detect_file_type(file_path)

    if file_extension == ".exe":
        scan_exe_file(file_path)

    with open(file_path, 'rb') as file:
        raw_data = file.read()
        encoding = chardet.detect(raw_data).get('encoding', 'utf-8')
        content = raw_data.decode(encoding, errors='ignore')

    webhook_pattern = r'https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+'
    webhooks = re.findall(webhook_pattern, content)

    app_id_pattern = r'\b\d{17,19}\b'
    app_ids = re.findall(app_id_pattern, content)

    rat_keywords = ['cmd.exe', 'powershell', 'reverse shell', 'exfiltrate', 'backdoor', 'malware']
    suspicious_urls = ['http://', 'https://', 'ftp://', 'file://', 'localhost', '192.168.', '10.']

    rat_found = any(keyword in content.lower() for keyword in rat_keywords)
    suspicious_url_found = any(url in content for url in suspicious_urls)

    if webhooks:
        print("Found Discord Webhooks:")
        for webhook in webhooks:
            print(f"  {webhook}")
    else:
        print(GREEN + "✔ No Discord Webhooks found." + RESET)

    if app_ids:
        print("\nPossible Discord Application IDs:")
        for app_id in app_ids:
            print(f"  {app_id}")
    else:
        print(GREEN + "✔ No Discord Application IDs found." + RESET)

    if rat_found or suspicious_url_found:
        print(RED + "\n✖ Potential Threat Detected!" + RESET)
        if rat_found:
            print(RED + "  - Possible RAT (Remote Access Trojan) or backdoor detected!" + RESET)
        if suspicious_url_found:
            print(RED + "  - Suspicious URLs or connections detected!" + RESET)
    else:
        print(GREEN + "\n✔ No obvious RAT, malware, or virus detected." + RESET)

    ask_for_online_scan(file_path)

def ask_for_online_scan(file_path):
    """Asks if the user wants to upload the file to an online scanner."""
    choice = input("\nDo you want to scan this file online? (y/N): ").strip().lower()
    if choice == 'y':
        open_online_scanners(file_path)
    else:
        print("Skipping online scan.")

def open_online_scanners(file_path):
    """Opens multiple virus scanning websites in the web browser for manual upload."""
    print("\nOpening online virus scanners...\n")

    virus_scanners = [
        "https://www.virustotal.com/gui/home/upload",
        "https://opentip.kaspersky.com/",
        "https://www.hybrid-analysis.com/",
        "https://www.metadefender.com/",
        "https://www.joesandbox.com/"
    ]

    for scanner in virus_scanners:
        webbrowser.open(scanner)

    print("Please manually upload the file to the opened scanners.")

def main():
    """Main function to get user input and start scanning."""
    clear_screen()
    print_header()

    print("Enter the full file path to scan for Discord Webhooks, App IDs, and potential threats.")
    file_path = input("\nFile Path: ").strip()

    if not os.path.exists(file_path):
        print("Error: The file does not exist.")
        return

    scan_file(file_path)

if __name__ == "__main__":
    main()
