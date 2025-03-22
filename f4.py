import pyfiglet
import random
import subprocess
import threading

# Display title
ascii_art = pyfiglet.figlet_format("FIREWALL RULES")
print(ascii_art)


def generate_random_ip():
    """Generate a random IP address."""
    return f"192.168.1.{random.randint(0, 20)}"


def load_ips_from_file(filename):
    """Load IPs from a file into a set."""
    try:
        with open(filename, "r") as f:
            return set(line.strip() for line in f.readlines())
    except FileNotFoundError:
        return set()


def save_ips_to_file(ips, filename):
    """Save a set of IPs to a file."""
    with open(filename, "w") as f:
        for ip in ips:
            f.write(ip + "\n")


def scan_vulnerabilities(ip):
    """Scan an IP using Nmap and return if it's vulnerable."""
    print(f"🔍 Scanning {ip} for vulnerabilities...")
    try:
        result = subprocess.run(["nmap", "-sV", "--script", "vuln", ip], capture_output=True, text=True)
        if "VULNERABLE" in result.stdout:
            return "Vulnerability found!"
        return None
    except Exception as e:
        return f"Error scanning {ip}: {str(e)}"


def get_user_ips(prompt):
    """Take user input for blocked or whitelisted IPs."""
    ips = set()
    print(f"\n{prompt} Type 'done' to finish.")
    while True:
        user_input = input("Enter IP: ").strip()
        if user_input.lower() == "done":
            break
        elif user_input.startswith("192.168.1.") and user_input[10:].isdigit():
            ips.add(user_input)
        else:
            print("⚠ Invalid format! Use 192.168.1.X (X = 0-20).")
    return ips


def scan_and_check(ip, blocked_ips, allowed_ips):
    """Scan an IP and determine whether to allow or block it."""
    if ip in allowed_ips:
        print(f"✅ IP: {ip} is WHITELISTED! Skipping scan.")
        return

    vulnerability = scan_vulnerabilities(ip)
    if vulnerability:
        print(f"❌ IP: {ip} is VULNERABLE! - BLOCKED 🚫")
        blocked_ips.add(ip)
    else:
        print(f"IP: {ip} is SAFE - ALLOWED ✅")
        allowed_ips.add(ip)


def main():
    blocked_ips = load_ips_from_file("blocked_ips.txt")
    allowed_ips = load_ips_from_file("allowed_ips.txt")

    blocked_ips.update(get_user_ips("🔴 Enter IPs to BLOCK."))
    allowed_ips.update(get_user_ips("🟢 Enter IPs to ALLOW."))

    num_ips = int(input("\nEnter the number of random IPs to generate: "))
    print("\n🔹 Simulating network traffic...\n")

    threads = []
    for _ in range(num_ips):
        ip_address = generate_random_ip()
        t = threading.Thread(target=scan_and_check, args=(ip_address, blocked_ips, allowed_ips))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    save_ips_to_file(blocked_ips, "blocked_ips.txt")
    save_ips_to_file(allowed_ips, "allowed_ips.txt")

    print("\n🚨 BLOCKED IPs 🚨")
    print(", ".join(blocked_ips) if blocked_ips else "None")
    print("\n✅ ALLOWED IPs ✅")
    print(", ".join(allowed_ips) if allowed_ips else "None")


if __name__ == "__main__":
    main()
