import random
import ipaddress
import csv

MAC_PREFIXES = {
    "Dell": "00:14:22", "HP": "3C:D9:2B", "Lenovo": "F4:8E:38", "Apple": "F0:99:BF",
    "Cisco": "00:25:9C", "Epson": "00:1B:44", "Generic": "00:16:3E"
}

OS_PERSONALITIES = {
    "desktop": ["Windows 10 Professional", "Ubuntu 20.04 LTS"],
    "laptop": ["Windows 11", "Linux 5.0"],
    "printer": ["Linux 5.0"],
    "server": ["Windows Server 2019", "Ubuntu 22.04"],
    "dmz": ["Cisco IOS 15.2", "Linux 5.4"],
    "web": ["Ubuntu 20.04", "CentOS 8"],
    "mail": ["Windows Server 2016", "Linux 5.0"]
}

PORT_SCRIPTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3",
    135: "epmap", 139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    3389: "rdp", 515: "printer", 161: "snmp"
}

DEVICE_CATEGORIES = {
    "desktop": {"count": 5, "mac": "Dell", "ports": [3389], "subnet": "10.0.10.0/24"},
    "laptop": {"count": 2, "mac": "Lenovo", "ports": [3389], "subnet": "10.0.20.0/24"},
    "printer": {"count": 2, "mac": "Epson", "ports": [80, 161, 515], "subnet": "10.0.30.0/24"},
    "server": {"count": 2, "mac": "HP", "ports": [139, 445, 135], "subnet": "10.0.40.0/24"},
    "dmz": {"count": 2, "mac": "Cisco", "ports": [22, 21, 80], "subnet": "10.0.50.0/24"},
    "web": {"count": 2, "mac": "Generic", "ports": [80, 443], "subnet": "10.0.60.0/24"},
    "mail": {"count": 2, "mac": "HP", "ports": [25, 110, 143], "subnet": "10.0.70.0/24"}
}

def generate_mac(vendor):
    prefix = MAC_PREFIXES[vendor]
    suffix = ":".join(["{:02x}".format(random.randint(0x00, 0xFF)) for _ in range(3)])
    return "{}:{}".format(prefix, suffix)

def generate_hostname(device_type, mac, i):
    if device_type in ["desktop", "laptop"]:
        mac_suffix = mac.split(":")[-1].upper()
        return "{}-{}-{}-{:02d}".format(device_type, DEVICE_CATEGORIES[device_type]["mac"].lower(), mac_suffix, i)
    else:
        return "{}-{:03d}".format(device_type, i)

def generate_honeyd_config(conf_file, csv_file):
    config_lines = []
    inventory = []

    for device_type in DEVICE_CATEGORIES:
        info = DEVICE_CATEGORIES[device_type]
        subnet = ipaddress.ip_network(unicode(info["subnet"]))
        current_ip = subnet.network_address + 1

        for i in xrange(1, info["count"] + 1):
            mac = generate_mac(info["mac"])
            hostname = generate_hostname(device_type, mac, i)
            ip = str(current_ip)
            os_personality = random.choice(OS_PERSONALITIES[device_type])
            services = []

            lines = [
                "create {}".format(hostname),
                "set {} personality \"{}\"".format(hostname, os_personality),
                "set {} ethernet \"{}\"".format(hostname, mac),
                "set {} default tcp action reset".format(hostname)
            ]

            for port in info["ports"]:
                script = PORT_SCRIPTS.get(port, "generic")
                lines.append('add {} tcp port {} "/usr/share/honeyd/scripts/{}"'.format(hostname, port, script))
                services.append("{}:{}".format(port, script))

            lines.append("bind {} {}".format(ip, hostname))
            config_lines.append("\n".join(lines))

            inventory.append([ip, hostname, mac, os_personality, device_type, ";".join(services)])
            current_ip += 1

    # Write config
    with open(conf_file, "w") as f:
        f.write("\n\n".join(config_lines))

    # Write CSV
    with open(csv_file, "wb") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Hostname", "MAC", "OS", "DeviceType", "Services"])
        writer.writerows(inventory)

    print("[+] Config saved to {}".format(conf_file))
    print("[+] Inventory saved to {}".format(csv_file))

# ========== Main ==========
if __name__ == "__main__":
    generate_honeyd_config("realistic_honeyd.conf", "inventory.csv")
