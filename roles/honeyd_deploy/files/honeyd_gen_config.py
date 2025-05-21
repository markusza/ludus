import random
import csv
import ipaddress
import os
import subprocess

def assign_interface_ip(subnet_str, interface="ens18"):
    net = ipaddress.ip_network(unicode(subnet_str))
    ip = str(list(net.hosts())[-1])  # Get last usable IP
    cmd = ["ip", "addr", "add", "{}/24".format(ip), "dev", interface]
    try:
        subprocess.check_call(cmd)
        print("[+] Assigned IP {} to {}".format(ip, interface))
    except Exception as e:
        print("[-] Could not assign IP {} to {}: {}".format(ip, interface, e))

# Patch for Python 2
try:
    unicode
except NameError:
    unicode = str

try:
    xrange
except NameError:
    xrange = range

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
    21: "linux/ftp.sh",
    22: "linux/ssh.sh",
    23: "misc/telnet",
    25: "linux/sendmail.sh",
    80: "linux/httpd/httpd.tcl",
    110: "linux/qpop.sh",
    135: "misc/base.sh",
    139: "misc/smb-autofail.py",
    143: "linux/cyrus-imapd.sh",
    443: "linux/httpd/httpd.tcl",
    445: "misc/smb-autofail.py",
    3389: "win32/win2k/vnc.sh",
    515: "linux/lpd.sh",
    161: "embedded/snmp"
}

naming_function_pool = {
    "server": random.sample(["files", "dbase", "authn", "print", "cache", "proxy", "vault", "dhcpd", "syncs", "sched"], 10),
    "web": random.sample(["login", "order", "forum", "media", "cms01", "authn", "search", "reset", "promo", "view1"], 10),
    "dmz": random.sample(["fwall", "vpn01", "mailr", "sshrv", "relay", "trap1", "scanr", "guard", "fwlog", "sensor"], 10)
}
function_counters = {k: {} for k in naming_function_pool}

DEVICE_CATEGORIES = {
    "desktop": {"count": 5, "mac": "Dell", "ports": [3389], "subnet": "10.2.30.0/24"},
    "laptop": {"count": 2, "mac": "Lenovo", "ports": [3389], "subnet": "10.2.40.0/24"},
    "printer": {"count": 2, "mac": "Epson", "ports": [80, 161, 515], "subnet": "10.2.50.0/24"},
    "server": {"count": 2, "mac": "HP", "ports": [139, 445, 135], "subnet": "10.2.60.0/24"},
    "dmz": {"count": 2, "mac": "Cisco", "ports": [22, 21, 80], "subnet": "10.2.80.0/24"},
    "web": {"count": 2, "mac": "Generic", "ports": [80, 443], "subnet": "10.2.81.0/24"},
    "mail": {"count": 2, "mac": "HP", "ports": [25, 110, 143], "subnet": "10.2.82.0/24"}
}

def generate_mac(vendor):
    prefix = MAC_PREFIXES[vendor]
    suffix = ":".join(["{:02x}".format(random.randint(0x00, 0xFF)) for _ in range(3)])
    return "{}:{}".format(prefix, suffix)

def generate_hostname(device_type, mac, i):
    if device_type in ["desktop", "laptop"]:
        mac_suffix = mac.split(":")[-1].upper()
        return "{}-{}-{}-{:02d}".format(device_type, DEVICE_CATEGORIES[device_type]["mac"].lower(), mac_suffix, i)
    elif device_type in naming_function_pool:
        pool = naming_function_pool[device_type]
        func_name = pool[i % len(pool)]
        count = function_counters[device_type].get(func_name, 0) + 1
        function_counters[device_type][func_name] = count
        return "{}-{}-{:02d}".format(device_type, func_name, count)
    else:
        return "{}-{:03d}".format(device_type, i)


def generate_honeyd_config(conf_file, csv_file):
    config_lines = []
    inventory = []

    for device_type in DEVICE_CATEGORIES:
        info = DEVICE_CATEGORIES[device_type]
        subnet = ipaddress.ip_network(unicode(info["subnet"]))
        current_ip = subnet.network_address + 1
        assign_interface_ip(info["subnet"])

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
                script = PORT_SCRIPTS.get(port)
                if script:
                    full_path = "/usr/share/honeyd/scripts/{}".format(script)
                    lines.append('add {} tcp port {} "{}"'.format(hostname, port, full_path))
                    services.append("{}:{}".format(port, script))

            lines.append("bind {} {}".format(ip, hostname))
            config_lines.append("\n".join(lines))

            inventory.append([ip, hostname, mac, os_personality, device_type, ";".join(services)])
            current_ip += 1

    with open(conf_file, "w") as f:
        f.write("\n\n".join(config_lines))

    with open(csv_file, "wb") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Hostname", "MAC", "OS", "DeviceType", "Services"])
        writer.writerows(inventory)

    print("[+] Config saved to {}".format(conf_file))
    print("[+] Inventory saved to {}".format(csv_file))

# Run it
if __name__ == "__main__":
    generate_honeyd_config("realistic_honeyd.conf", "inventory.csv")
