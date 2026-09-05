import socket
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import os
import re
import functools
from ipaddress import ip_network
import logging
import socks
import ssl
from faker import Faker

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    sys.stdout.reconfigure(line_buffering=False, write_through=True)
except (AttributeError, ValueError):
    pass

print = functools.partial(print, flush=True)

from scapy.all import IP, TCP, UDP, ICMP, sr1, sr


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    ORANGE = '\033[38;2;255;165;0m'
    DIM_GRAY = '\033[38;2;110;110;120m'
    NEON_CYAN = '\033[38;2;0;255;213m'
    NEON_PURPLE = '\033[38;2;191;64;255m'
    CORNFLOWER_BLUE = '\033[38;2;100;149;237m'
    SKY_BLUE = '\033[38;2;135;206;235m'
    FRAME = '\033[38;2;138;92;246m'
    CRIMSON = '\033[38;2;220;20;60m'
    AQUA = '\033[38;2;0;255;255m'
    TEAL = '\033[38;2;0;128;128m'
    GOLD = '\033[38;2;255;215;0m'


SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPC", 135: "MSRPC", 139: "NETBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    27017: "MongoDB", 8000: "HTTP-ALT", 8001: "HTTP-ALT",
    8003: "HTTP-ALT", 3000: "HTTP-ALT", 5000: "HTTP-ALT"
}

UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 69: "TFTP", 123: "NTP",
    137: "NETBIOS-NS", 161: "SNMP", 162: "SNMP-TRAP",
    500: "IKE", 514: "SYSLOG", 1900: "SSDP", 5353: "MDNS"
}


def get_service(port):
    return SERVICES.get(port, "")


def get_udp_service(port):
    return UDP_SERVICES.get(port, "")


def get_os_simple(ttl):
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Network Device"
    else:
        return "Unknown"


def get_os_from_ttl(ttl):
    if ttl <= 32:
        return "Windows 95/98"
    elif ttl <= 64:
        return "Linux/Unix/macOS/Android"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 200:
        return "IRIX"
    elif ttl <= 254:
        return "Solaris"
    elif ttl <= 255:
        return "Cisco/Router/Juniper"
    else:
        return "Unknown"


def os_scan_banner():
    print(Colors.CRIMSON + """
   ██████╗ ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔═══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║   ██║███████╗    ███████╗██║     ███████║██╔██╗ ██║
  ██║   ██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚██████╔╝███████║    ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
""" + Colors.RESET)
    print(Colors.CRIMSON + "OS DETECTION SCANNER".center(58) + Colors.RESET)
    print(Colors.DIM_GRAY + "-" * 58 + Colors.RESET)


def os_scan_only(target):
    os.system("clear" if os.name == "posix" else "cls")
    os_scan_banner()

    print(Colors.GOLD + f"\n[*] OS Detection for {target}..." + Colors.RESET)
    print(Colors.DIM_GRAY + f"[*] Trying multiple ports..." + Colors.RESET)
    print()

    ports = [80, 443]

    for port in ports:
        try:
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=2, verbose=0)

            if resp and resp.haslayer(IP):
                ttl = resp[IP].ttl
                os_type = get_os_from_ttl(ttl)

                print(Colors.GREEN + f"[+] Port {port} responded! TTL={ttl}" + Colors.RESET)
                print(Colors.NEON_CYAN + f"[+] Detected OS: {os_type}" + Colors.RESET)
                print()

                save_choice = typed_input(Colors.AQUA + "[?] Save results? [txt/n]: " + Colors.RESET).strip().lower()

                if save_choice == "txt":
                    filename = f"os_scan_{target.replace('.', '_')}_{int(time.time())}.txt"
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write("=" * 60 + "\n")
                        f.write("  OS DETECTION SCANNER - RESULTS\n")
                        f.write("=" * 60 + "\n\n")
                        f.write(f"Target      : {target}\n")
                        f.write(f"Port        : {port}\n")
                        f.write(f"TTL         : {ttl}\n")
                        f.write(f"OS          : {os_type}\n")
                        f.write("\n" + "=" * 60 + "\n")
                        f.write("  t.me/xomlsx\n")
                        f.write("=" * 60 + "\n")
                    print(Colors.GREEN + f"[+] File saved: {filename}" + Colors.RESET)

                print(Colors.FRAME + "=" * 58 + Colors.RESET)
                print(Colors.YELLOW + "\n-xomlsx-" + Colors.RESET)
                print(Colors.BLUE + "t.me/xomlsx" + Colors.RESET)
                return os_type

        except:
            continue

    print(Colors.RED + "[!] OS not detected!" + Colors.RESET)
    print(Colors.FRAME + "=" * 58 + Colors.RESET)
    print(Colors.YELLOW + "\n-xomlsx-" + Colors.RESET)
    print(Colors.BLUE + "t.me/xomlsx" + Colors.RESET)
    return "Unknown"


def enable_tor():
    try:
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect_ex(("check.torproject.org", 80))
        s.sendall(b"HEAD / HTTP/1.0\r\nHost: check.torproject.org\r\n\r\n")
        data = s.recv(1024)
        s.close()

        if data:
            print(Colors.GREEN + "[+] Tor is active!" + Colors.RESET)
            return True
        else:
            print(Colors.RED + "[-] Tor test failed!" + Colors.RESET)
            return False
    except Exception as e:
        print(Colors.RED + f"[-] Tor error: {e}" + Colors.RESET)
        return False


def tor_scan(target, ports, timeout=1.0):
    open_ports = []
    banners = {}

    print(Colors.GOLD + f"\n[*] Scanning {target} through Tor..." + Colors.RESET)
    print(Colors.DIM_GRAY + f"[*] Total ports to scan: {len(ports)}" + Colors.RESET)
    print()

    scanned_count = 0
    total_ports = len(ports)

    payloads = {
        80: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        443: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        8080: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        8443: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        8000: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        3000: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        5000: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        25: b"EHLO test\r\n",
        6379: b"PING\r\n",
    }

    def scan_tor(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target, port))

            banner = ""

            if result == 0:
                try:
                    if port in payloads and payloads[port]:
                        s.sendall(payloads[port])
                        data = s.recv(2048)
                        banner = data.decode(errors="ignore").strip()

                        if "Server:" in banner:
                            for line in banner.splitlines():
                                if "Server:" in line:
                                    banner = line.strip()
                                    break
                        elif "HTTP/" in banner:
                            banner = banner.splitlines()[0] if banner else ""
                        else:
                            banner = banner[:80]
                except:
                    pass

            s.close()

            if result == 0:
                return port, True, banner
            else:
                return port, False, ""
        except:
            return port, False, ""

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(scan_tor, port): port for port in ports}

        for future in as_completed(futures):
            scanned_count += 1
            progress_bar(scanned_count, total_ports)

            port, is_open, banner = future.result()

            if is_open:
                open_ports.append(port)
                if banner:
                    banners[port] = banner

                with print_lock:
                    sys.stdout.write("\r" + " " * 120 + "\r")
                    sys.stdout.flush()

                    service = get_service(port)
                    tag = f"<{service}>" if service else ""
                    banner_txt = f" | {banner}" if banner else ""

                    print(
                        Colors.NEON_CYAN +
                        f"[+] Port {port} OPEN (Tor) ---> " +
                        Colors.GREEN + f"{tag}" +
                        Colors.DIM_GRAY + f"{banner_txt}" +
                        Colors.RESET
                    )

    sys.stdout.write("\n")
    sys.stdout.flush()

    return open_ports, banners


def multi_target_scan(targets, scan_type, check_os=False, thread_count=100, timeout=1.0):
    all_results = {}

    for target in targets:
        target = target.strip()
        if not target:
            continue

        ip, hostname = resolve_target(target)

        if hostname == "N/A" and ip == target:
            print(Colors.RED + f"[-] Can't resolve: {target}" + Colors.RESET)
            continue

        print(Colors.BLUE + f"\n[*] Scanning {target} ({ip})..." + Colors.RESET)

        open_ports = []
        banners = {}
        os_type = "Not checked"

        ports = sorted(SERVICES.keys())

        if scan_type == "2":
            scan_func = syn_scan_port
        elif scan_type == "3":
            scan_func = udp_scan_port
        else:
            scan_func = scan_port

        scanned_count = 0
        total_ports = len(ports)

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            if check_os and scan_type == "2":
                futures = {executor.submit(scan_func, ip, port, timeout, True): port for port in ports}
            else:
                futures = {executor.submit(scan_func, ip, port, timeout): port for port in ports}

            for future in as_completed(futures):
                scanned_count += 1
                progress_bar(scanned_count, total_ports)

                try:
                    result = future.result()

                    if scan_type == "2":
                        port, status, banner, os_result = result
                        if check_os and os_type == "Not checked" and os_result != "Unknown":
                            os_type = os_result
                    else:
                        port, status, banner = result

                    is_open = status == "OPEN" if scan_type == "3" else bool(status)

                    if is_open:
                        open_ports.append(port)
                        if banner:
                            banners[port] = banner
                except:
                    pass

        sys.stdout.write("\n" + " " * 120 + "\r")
        sys.stdout.flush()

        all_results[target] = {
            "ip": ip,
            "open_ports": sorted(set(open_ports)),
            "banners": banners,
            "os_type": os_type
        }

        print(Colors.GOLD + f"  [*] {target}: {len(open_ports)} open port(s)" + Colors.RESET)

    return all_results


print_lock = threading.Lock()


def strip_ansi(text):
    return re.sub(r'\033\[[0-9;]*m', '', text)


def _raw_write(text):
    os.write(sys.stdout.fileno(), text.encode(errors="ignore"))


def typed_input(prompt, delay=0.035):
    i = 0
    while i < len(prompt):
        ch = prompt[i]

        if ch == '\033':
            m = re.match(r'\033\[[0-9;]*m', prompt[i:])
            if m:
                _raw_write(m.group(0))
                i += len(m.group(0))
                continue

        _raw_write(ch)
        time.sleep(delay)
        i += 1

    return input()


def typed_print(text, delay=0.025, end="\n"):
    i = 0
    while i < len(text):
        ch = text[i]

        if ch == '\033':
            m = re.match(r'\033\[[0-9;]*m', text[i:])
            if m:
                _raw_write(m.group(0))
                i += len(m.group(0))
                continue

        _raw_write(ch)
        time.sleep(delay)
        i += 1

    _raw_write(end)


def box_line(text, width=58, color=Colors.FRAME, text_color=Colors.WHITE):
    inner = width - 2
    clean_text = strip_ansi(text)

    if len(clean_text) > inner:
        text_parts = re.split(r'(\033\[[0-9;]*m)', text)
        current_len = 0
        new_text = ""

        for part in text_parts:
            if part.startswith('\033'):
                new_text += part
            else:
                remaining = inner - current_len
                if len(part) <= remaining:
                    new_text += part
                    current_len += len(part)
                else:
                    new_text += part[:remaining]
                    break

        text = new_text
        clean_text = clean_text[:inner]

    pad = inner - len(clean_text)
    print(
        color + "| " + Colors.RESET +
        text_color + text +
        " " * max(0, pad - 1) +
        color + " |" + Colors.RESET
    )


def box_top(width=58, color=Colors.FRAME):
    print(color + "+" + "-" * (width - 2) + "+" + Colors.RESET)


def box_bottom(width=58, color=Colors.FRAME):
    print(color + "+" + "-" * (width - 2) + "+" + Colors.RESET)


def box_divider(width=58, color=Colors.FRAME):
    print(color + "+" + "-" * (width - 2) + "+" + Colors.RESET)


def progress_bar(current, total, bar_length=40):
    if total <= 0:
        return

    progress = current / total
    block = int(round(bar_length * progress))

    text = (
        f"\r[{Colors.GREEN}{'█' * block}"
        f"{Colors.DIM_GRAY}{'░' * (bar_length - block)}"
        f"{Colors.RESET}] {int(progress * 100)}%"
    )

    sys.stdout.write(text)
    sys.stdout.flush()


def resolve_target(target):
    try:
        socket.inet_aton(target)
        ip = target
    except OSError:
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return target, "N/A"

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = "N/A"

    return ip, hostname


def ping_sweep(network, timeout=1):
    alive_hosts = []

    try:
        ips = [str(ip) for ip in ip_network(network, strict=False).hosts()]

        print(Colors.GOLD + f"\n[*] Ping Sweep on {network}..." + Colors.RESET)
        print(Colors.DIM_GRAY + f"[*] Total IPs to check: {len(ips)}" + Colors.RESET)

        def check_host(ip):
            try:
                pkt = IP(dst=ip) / ICMP()
                resp = sr1(pkt, timeout=timeout, verbose=0)

                if resp:
                    ttl = resp[IP].ttl
                    return ip, True, ttl
                else:
                    return ip, False, None
            except Exception:
                return ip, False, None

        scanned_count = 0
        total_ips = len(ips)

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_host, ip): ip for ip in ips}

            for future in as_completed(futures):
                scanned_count += 1
                progress_bar(scanned_count, total_ips)

                ip, is_alive, ttl = future.result()

                if is_alive:
                    alive_hosts.append((ip, ttl))

                    with print_lock:
                        sys.stdout.write("\r" + " " * 120 + "\r")
                        sys.stdout.flush()
                        print(Colors.GREEN + f"[+] {ip} is ALIVE (TTL={ttl})" + Colors.RESET)

        sys.stdout.write("\n" + " " * 120 + "\r")
        sys.stdout.flush()

        return alive_hosts

    except Exception as e:
        print(Colors.RED + f"[!] Error: {e}" + Colors.RESET)
        return []


def subdomain_scanner(domain, timeout=2):
    subdomains = [
        "www", "mail", "ftp", "admin", "api", "dev", "test",
        "blog", "shop", "cdn", "dns", "vpn", "remote", "portal",
        "secure", "login", "dashboard", "panel", "webmail", "ns1", "ns2"
    ]

    found_subdomains = []

    print(Colors.GOLD + f"\n[*] Scanning subdomains for {domain}..." + Colors.RESET)
    print(Colors.DIM_GRAY + f"[*] Total subdomains to check: {len(subdomains)}" + Colors.RESET)

    def check_subdomain(sub):
        try:
            full_domain = f"{sub}.{domain}"
            ip = socket.gethostbyname(full_domain)
            return full_domain, ip, True
        except socket.gaierror:
            return full_domain, "", False
        except Exception:
            return full_domain, "", False

    scanned_count = 0
    total_subs = len(subdomains)

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}

        for future in as_completed(futures):
            scanned_count += 1
            progress_bar(scanned_count, total_subs)

            full_domain, ip, is_found = future.result()

            if is_found:
                found_subdomains.append((full_domain, ip))

                with print_lock:
                    sys.stdout.write("\r" + " " * 120 + "\r")
                    sys.stdout.flush()
                    print(Colors.GREEN + f"[+] {full_domain} --> {ip}" + Colors.RESET)

    sys.stdout.write("\n" + " " * 120 + "\r")
    sys.stdout.flush()

    return found_subdomains


def grab_banner_from_udp(target, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.settimeout(timeout)
        s.sendto(b"", (target, port))
        data, _ = s.recvfrom(1024)
        return data.decode(errors="ignore").strip()[:80]
    except (socket.timeout, OSError):
        return ""
    finally:
        s.close()


def udp_scan_port(target, port, timeout):
    try:
        pkt = IP(dst=target) / UDP(dport=port)
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            return port, "OPEN|FILTERED", ""

        if resp.haslayer(ICMP):
            icmp = resp[ICMP]

            if icmp.type == 3 and icmp.code == 3:
                return port, "CLOSED", ""

            if icmp.type == 3 and icmp.code in [1, 2, 9, 10, 13]:
                return port, "FILTERED", ""

        if resp.haslayer(UDP):
            banner = grab_banner_from_udp(target, port, timeout)
            return port, "OPEN", banner

        return port, "UNKNOWN", ""

    except Exception:
        return port, "UNKNOWN", ""


def get_version_banner(target, port, timeout=2.0):
    payloads = {
        21: b"", 22: b"", 23: b"", 25: b"EHLO test\r\n",
        53: b"", 80: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        110: b"", 111: b"", 135: b"", 139: b"", 143: b"",
        443: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        445: b"", 993: b"", 995: b"", 1723: b"",
        3306: b"", 3389: b"", 5432: b"", 5900: b"",
        6379: b"PING\r\n", 8080: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        8443: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        27017: b"", 8000: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        8001: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        8003: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        3000: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        5000: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
    }

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.settimeout(timeout)

        if s.connect_ex((target, port)) != 0:
            return ""

        if port in [443, 8443, 993, 995]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname=target)
            except:
                pass

        payload = payloads.get(port, b"")
        if payload:
            s.sendall(payload)

        data = s.recv(2048)
        banner = data.decode(errors="ignore").strip()

        if port == 22 and "SSH-" in banner:
            parts = banner.split("-")
            if len(parts) >= 3:
                return f"SSH {parts[2]}"

        if port == 3306 and data:
            try:
                null_pos = data.index(b'\x00', 1)
                version = data[1:null_pos].decode(errors="ignore")
                return f"MySQL {version}"
            except:
                pass

        if "HTTP/" in banner or "Server:" in banner:
            status_line = banner.splitlines()[0] if banner else ""
            server_line = ""

            for line in banner.splitlines():
                if "Server:" in line:
                    server_line = line.strip()
                    break

            if server_line:
                return f"{status_line} | {server_line}"

            return status_line

        return banner[:200]

    except (socket.timeout, OSError):
        return ""
    finally:
        s.close()


def scan_port(target, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
        finally:
            s.close()

        is_open = result == 0
        banner = ""

        if is_open:
            banner = get_version_banner(target, port, timeout)

            with print_lock:
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()

                service = get_service(port)
                tag = f"<{service}>" if service else ""
                banner_txt = f" | {banner}" if banner else ""

                print(
                    Colors.NEON_CYAN +
                    f"[+] Port {port} OPEN --> " +
                    Colors.GREEN + f"{tag}" +
                    Colors.DIM_GRAY + f"{banner_txt}" +
                    Colors.RESET
                )

        return port, is_open, banner

    except socket.gaierror:
        raise
    except Exception:
        return port, False, ""


def syn_scan_port(target, port, timeout, check_os=False):
    try:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if not resp or not resp.haslayer(TCP):
            return port, False, "", "Unknown"

        flags = int(resp[TCP].flags)

        if flags == 0x12:
            os_type = "Unknown"

            if check_os:
                ttl = resp[IP].ttl
                os_type = get_os_simple(ttl)

            rst_pkt = (
                    IP(dst=target) /
                    TCP(
                        dport=port,
                        sport=resp[TCP].dport,
                        seq=resp[TCP].ack,
                        ack=resp[TCP].seq + 1,
                        flags="R"
                    )
            )
            sr(rst_pkt, timeout=0.5, verbose=0)

            banner = get_version_banner(target, port, timeout)

            with print_lock:
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()

                service = get_service(port)
                tag = f"<{service}>" if service else ""
                banner_txt = f" | {banner}" if banner else ""
                os_txt = f" | OS: {os_type}" if check_os and os_type != "Unknown" else ""

                print(
                    Colors.NEON_CYAN +
                    f"[+] Port {port} OPEN (SYN) ---> " +
                    Colors.GREEN + f"{tag}" +
                    Colors.DIM_GRAY + f"{banner_txt}" +
                    Colors.GOLD + f"{os_txt}" +
                    Colors.RESET
                )

            return port, True, banner, os_type

        return port, False, "", "Unknown"

    except Exception:
        return port, False, "", "Unknown"


def fin_scan_port(target, port, timeout):
    try:
        pkt = IP(dst=target) / TCP(dport=port, flags="F")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            return port, "OPEN|FILTERED", ""

        if resp.haslayer(TCP):
            flags = int(resp[TCP].flags)

            if flags == 0x14:
                return port, "CLOSED", ""
            else:
                return port, "OPEN", ""

        return port, "UNKNOWN", ""

    except Exception:
        return port, "UNKNOWN", ""


def fragment_scan_port(target, port, timeout):
    try:
        pkt = IP(dst=target, flags="MF") / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            return port, "FILTERED", ""

        if resp.haslayer(TCP):
            flags = int(resp[TCP].flags)

            if flags == 0x12:
                return port, "OPEN", ""
            elif flags == 0x14:
                return port, "CLOSED", ""

        return port, "UNKNOWN", ""

    except Exception:
        return port, "UNKNOWN", ""


def save_results_html(target, open_ports, banners, scan_time, os_type, hostname, scan_type):
    filename = f"scan_{target.replace('.', '_')}_{int(time.time())}.html"
    ip, _ = resolve_target(target)
    scan_type_text = "UDP" if scan_type == "3" else "TCP"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SCAN WORK</title>
</head>
<body>
    <h3>SCAN WORK</h3>
    <table border="1" width="80%" cellpadding="15" cellspacing="0">
        <tr>
            <td width="30%" align="center"><font size="3"><strong>Target</strong></font></td>
            <td width="70%" align="center"><font size="3">{target}</font></td>
        </tr>
        <tr>
            <td align="center"><font size="3"><strong>IP</strong></font></td>
            <td align="center"><font size="3">{ip}</font></td>
        </tr>
        <tr>
            <td align="center"><font size="3"><strong>OS</strong></font></td>
            <td align="center"><font size="3">{os_type}</font></td>
        </tr>
        <tr>
            <td align="center"><font size="3"><strong>Hostname</strong></font></td>
            <td align="center"><font size="3">{hostname}</font></td>
        </tr>
        <tr>
            <td align="center"><font size="3"><strong>Scan Type</strong></font></td>
            <td align="center"><font size="3">{scan_type_text}</font></td>
        </tr>
        <tr>
            <td align="center"><font size="3"><strong>Open Ports</strong></font></td>
            <td align="center"><font size="3">{len(open_ports)}</font></td>
        </tr>
        <tr>
            <td align="center"><font size="3"><strong>Time</strong></font></td>
            <td align="center"><font size="3">{scan_time:.2f}s</font></td>
        </tr>
    </table>

    <h2>OPEN PORTS</h2>
    <table border="1" width="80%" cellpadding="10" cellspacing="0">
        <tr>
            <td align="center"><font size="3"><strong>Port</strong></font></td>
            <td align="center"><font size="3"><strong>Service</strong></font></td>
            <td align="center"><font size="3"><strong>Banner</strong></font></td>
        </tr>
"""

    for p in open_ports:
        service = get_service(p)
        banner = banners.get(p, "")
        html += f"""        <tr>
            <td align="center"><font size="3">{p}</font></td>
            <td align="center"><font size="3">{service}</font></td>
            <td align="center"><font size="3">{banner}</font></td>
        </tr>
"""

    html += """    </table>
    <br>
    <p align="center">t.me/xomlsx</p>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename


def save_results(
        target,
        scan_type,
        open_ports,
        open_filtered_ports,
        filtered_ports,
        banners,
        scan_time,
        os_type,
        hostname
):
    filename = f"scan_{target.replace('.', '_')}_{int(time.time())}.txt"

    is_udp = scan_type == "3"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  SCAN WORK - RESULTS\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Target          : {target}\n")
        f.write(f"Hostname        : {hostname}\n")
        f.write(f"Scan Type       : {'UDP' if is_udp else 'TCP/SYN'}\n")
        f.write(f"OS              : {os_type}\n")
        f.write(f"Scan Time       : {scan_time:.2f} seconds\n")
        f.write(f"Open Ports      : {len(open_ports)}\n")

        if is_udp:
            f.write(f"Open|Filtered   : {len(open_filtered_ports)}\n")
            f.write(f"Filtered        : {len(filtered_ports)}\n")

        f.write("\n" + "-" * 60 + "\n")
        f.write("  RESULTS\n")
        f.write("-" * 60 + "\n")

        if open_ports:
            for p in open_ports:
                service = get_udp_service(p) if is_udp else get_service(p)
                banner = banners.get(p, "")
                f.write(
                    f"  Port {p:<6} {service:<15} "
                    f"OPEN"
                    f"{' | ' + banner if banner else ''}\n"
                )
        else:
            f.write("  No confirmed open ports found.\n")

        if is_udp and open_filtered_ports:
            f.write("\n  OPEN|FILTERED PORTS:\n")
            for p in open_filtered_ports:
                service = get_udp_service(p)
                f.write(f"  Port {p:<6} {service:<15} OPEN|FILTERED\n")

        if is_udp and filtered_ports:
            f.write("\n  FILTERED PORTS:\n")
            for p in filtered_ports:
                service = get_udp_service(p)
                f.write(f"  Port {p:<6} {service:<15} FILTERED\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("  t.me/xomlsx\n")
        f.write("=" * 60 + "\n")

    return filename


def main():
    os.system("clear" if os.name == "posix" else "cls")

    print(Colors.CRIMSON + """
 0-1-1-0-1-1-1-0-0-0-1-0-1-1-0-1-0-0-1-0-1
 0  ███████╗ ██████╗ █████╗ ███╗ 1 ██╗   1
 1  ██╔════╝██╔════╝██╔══██╗████╗1 ██║   0
 0  ███████╗██║0101 ███████║██╔██╗0██║   0
 1  ╚════██║██║0101 ██╔══██║██║╚██╗██║   1
 1  ███████║╚██████╗██║00██║██║0╚████║   1
 0  ╚═════╝ ╚═════╝╚ ═╝01 ╚═╝╚═╝1╚═══╝   0
 1  ██╗0101██╗ ██████╗ ██████╗ ██╗0 ██╗  1
 0  ██║ 01 ██║██╔═══██╗██╔══██╗██║1██╔╝  0
 1  ██║ █╗ ██║██║01 ██║██████╔╝█████╔╝   1
 0  ██║███╗██║██║00 ██║██╔══██╗██╔═██╗   0
 1  ╚███╔███╔╝╚██████╔╝██║0 ██║██║1 ██╗  1
 0   ╚══╝╚══╝  ╚═════╝ ╚═╝1 ╚═╝╚═╝ 0╚═╝  1
  - - - - - - - - - - - - - - - - - - - -
""" + Colors.RESET)
    print()

    box_top()
    box_line("SELECT SCAN MODE", text_color=Colors.NEON_CYAN + Colors.BOLD)
    box_divider()
    box_line("1) Multi-Target Scan", text_color=Colors.SKY_BLUE)
    box_line("2) Single Target Scan", text_color=Colors.SKY_BLUE)
    box_line("3) Ping Sweep (Network)", text_color=Colors.SKY_BLUE)
    box_line("4) Subdomain Scanner", text_color=Colors.SKY_BLUE)
    box_line("5) OS Detection Only", text_color=Colors.SKY_BLUE)
    box_line("6) Tor Scan", text_color=Colors.SKY_BLUE)
    box_line("7) Decoy Scan (IP Spoofing)", text_color=Colors.SKY_BLUE)
    box_bottom()

    scan_mode = typed_input(Colors.AQUA + "[?] Choose mode (1-7): " + Colors.RESET).strip()

    if scan_mode == "1":
        print(Colors.AQUA + "\n[*] Paste IPs (empty line to finish):" + Colors.RESET)
        targets = []

        while True:
            line = input()
            if line.strip() == "":
                break
            targets.append(line.strip())

        if not targets:
            print(Colors.RED + "[!] No targets entered!" + Colors.RESET)
            sys.exit(0)

        print(Colors.CYAN + f"[*] {len(targets)} targets loaded!" + Colors.RESET)

        print()
        box_top()
        box_line("SELECT SCAN SPEED", text_color=Colors.NEON_CYAN + Colors.BOLD)
        box_divider()
        box_line("1) Slow (15 Threads)", text_color=Colors.SKY_BLUE)
        box_line("2) Normal (50 Threads)", text_color=Colors.SKY_BLUE)
        box_line("3) Fast (100 Threads)", text_color=Colors.SKY_BLUE)
        box_line("4) Super Fast (200 Threads)", text_color=Colors.SKY_BLUE)
        box_bottom()

        multi_speed = typed_input(Colors.AQUA + "[?] Choose speed (1-4): " + Colors.RESET).strip()

        speed_settings_multi = {
            "1": (15, 4.0),
            "2": (50, 2.0),
            "3": (100, 1.0),
            "4": (200, 0.5),
        }

        thread_count_multi, timeout_multi = speed_settings_multi.get(multi_speed, (100, 1.0))

        print()
        box_top()
        box_line("SELECT SCAN TYPE", text_color=Colors.NEON_CYAN + Colors.BOLD)
        box_divider()
        box_line("1) TCP Scan", text_color=Colors.SKY_BLUE)
        box_line("2) SYN Scan", text_color=Colors.SKY_BLUE)
        box_line("3) UDP Scan", text_color=Colors.SKY_BLUE)
        box_bottom()

        multi_type = typed_input(Colors.AQUA + "[?] Choose scan type (1-3): " + Colors.RESET).strip()

        if multi_type == "2":
            os_choice_multi = typed_input(Colors.AQUA + "[?] Detect OS? [y/n]: " + Colors.RESET).strip().lower()
            check_os_multi = os_choice_multi in ["y", "yes"]
        else:
            check_os_multi = False

        results = multi_target_scan(targets, multi_type, check_os_multi, thread_count_multi, timeout_multi)

        print()
        box_top()
        box_line("MULTI SCAN RESULTS", text_color=Colors.NEON_CYAN + Colors.BOLD)
        box_divider()

        for target, data in results.items():
            box_line(f"Target: {target}", text_color=Colors.WHITE)
            box_line(f"IP: {data['ip']}", text_color=Colors.DIM_GRAY)
            box_line(f"Open Ports: {len(data['open_ports'])}",
                     text_color=Colors.GREEN if data['open_ports'] else Colors.RED)
            if data['os_type'] != "Not checked":
                box_line(f"OS: {data['os_type']}", text_color=Colors.GOLD)
            box_divider()
        box_bottom()

        sys.exit(0)

    if scan_mode == "2":
        target = typed_input(
            Colors.AQUA + "[#] Enter IP or Hostname: " + Colors.RESET
        ).strip()

        if not target:
            print(Colors.RED + "[!] No target entered." + Colors.RESET)
            sys.exit(1)

        ip, hostname = resolve_target(target)

        if hostname == "N/A" and ip == target:
            print(Colors.RED + "[!] Could not resolve target." + Colors.RESET)
            sys.exit(1)

        print(Colors.GREEN + f"[*] IP: {ip}" + Colors.RESET)
        print(Colors.GREEN + f"[*] Hostname: {hostname}" + Colors.RESET)

        print()
        box_top()
        box_line(
            "SELECT SCAN SPEED",
            text_color=Colors.NEON_CYAN + Colors.BOLD
        )
        box_divider()
        box_line("1) Super Slow", text_color=Colors.SKY_BLUE)
        box_line("2) Slow", text_color=Colors.SKY_BLUE)
        box_line("3) Normal", text_color=Colors.SKY_BLUE)
        box_line("4) Fast", text_color=Colors.SKY_BLUE)
        box_line("5) Super Fast", text_color=Colors.SKY_BLUE)
        box_bottom()

        speed_mode = typed_input(
            Colors.AQUA + "[?] Choose speed (1-5): " + Colors.RESET
        ).strip()

        speed_settings = {
            "1": (4.0, 21, "Super Slow"),
            "2": (2.0, 50, "Slow"),
            "3": (0.9, 200, "Normal"),
            "4": (0.3, 400, "Fast"),
            "5": (0.2, 550, "Super Fast"),
        }

        timeout, thread_count, speed_label = speed_settings.get(
            speed_mode,
            (0.9, 200, "Normal (default)")
        )

        print()
        box_top()
        box_line(
            "SELECT SCAN TYPE",
            text_color=Colors.NEON_CYAN + Colors.BOLD
        )
        box_divider()
        box_line("1) TCP Scan", text_color=Colors.SKY_BLUE)
        box_line("2) SYN Scan", text_color=Colors.SKY_BLUE)
        box_line("3) UDP Scan", text_color=Colors.SKY_BLUE)
        box_line("4) FIN Scan", text_color=Colors.SKY_BLUE)
        box_line("5) Fragment Scan", text_color=Colors.SKY_BLUE)
        box_bottom()

        scan_type = typed_input(
            Colors.AQUA + "[?] Choose scan type (1-5): " + Colors.RESET
        ).strip()

        if scan_type not in ["1", "2", "3", "4", "5"]:
            print(Colors.RED + "[!] Invalid scan type." + Colors.RESET)
            sys.exit(1)

        check_os = False
        os_type = "Not checked"

        if scan_type == "2":
            os_choice = typed_input(
                Colors.AQUA + "[?] Detect OS? [y/n]: " + Colors.RESET
            ).strip().lower()
            check_os = os_choice in ["y", "yes"]

        print()
        box_top()
        box_line(
            "SELECT PORT MODE",
            text_color=Colors.NEON_CYAN + Colors.BOLD
        )
        box_divider()
        box_line("1) Custom", text_color=Colors.SKY_BLUE)
        box_line("2) Well-known", text_color=Colors.SKY_BLUE)
        box_line("3) Full (1-65535)", text_color=Colors.SKY_BLUE)
        box_bottom()

        mode = typed_input(
            Colors.AQUA + "[?] Choose (1-3): " + Colors.RESET
        ).strip()

        if mode == "1":
            port_input = typed_input(
                Colors.AQUA +
                "[?] Enter ports/ranges (1-1000): " +
                Colors.RESET
            )

            try:
                ports = []

                for chunk in port_input.split(","):
                    chunk = chunk.strip()

                    if not chunk:
                        continue

                    if "-" in chunk:
                        parts = chunk.split("-", 1)
                        start_p = int(parts[0].strip())
                        end_p = int(parts[1].strip())

                        if start_p > end_p:
                            start_p, end_p = end_p, start_p

                        if start_p < 1 or end_p > 65535:
                            raise ValueError

                        ports.extend(range(start_p, end_p + 1))

                    else:
                        port = int(chunk)

                        if port < 1 or port > 65535:
                            raise ValueError

                        ports.append(port)

                ports = list(dict.fromkeys(ports))

                if not ports:
                    raise ValueError

            except ValueError:
                print(
                    Colors.RED +
                    "[!] Invalid port list. Use values from 1-65535." +
                    Colors.RESET
                )
                sys.exit(1)

        elif mode == "2":
            if scan_type == "3":
                ports = sorted(UDP_SERVICES.keys())
                print(
                    Colors.CYAN +
                    f"[*] Loaded {len(ports)} well-known UDP ports." +
                    Colors.RESET
                )
            else:
                ports = sorted(SERVICES.keys())
                print(
                    Colors.CYAN +
                    f"[*] Loaded {len(ports)} well-known TCP ports." +
                    Colors.RESET
                )

        elif mode == "3":
            ports = range(1, 65536)
            print(
                Colors.MAGENTA +
                "[*] Full range selected." +
                Colors.RESET
            )

        else:
            print(Colors.RED + "[!] Invalid option." + Colors.RESET)
            sys.exit(1)

        print("\n" + "=" * 36)
        print(
            Colors.BLUE +
            f"\n[*] Scanning {target}..." +
            Colors.RESET
        )
        print(
            Colors.DIM_GRAY +
            f"[*] Speed: {speed_label} | "
            f"Timeout: {timeout}s | Threads: {thread_count}" +
            Colors.RESET
        )
        print(
            Colors.DIM_GRAY +
            f"[*] Total ports to scan: {len(ports)}" +
            Colors.RESET
        )

        start_time = time.time()

        open_ports = []
        open_filtered_ports = []
        filtered_ports = []
        banners = {}

        scanned_count = 0
        total_ports = len(ports)

        if scan_type == "2":
            scan_func = syn_scan_port
        elif scan_type == "3":
            scan_func = udp_scan_port
        elif scan_type == "4":
            scan_func = fin_scan_port
        elif scan_type == "5":
            scan_func = fragment_scan_port
        else:
            scan_func = scan_port

        try:
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                if check_os and scan_type == "2":
                    futures = {
                        executor.submit(scan_func, ip, port, timeout, True): port
                        for port in ports
                    }
                else:
                    futures = {
                        executor.submit(scan_func, ip, port, timeout): port
                        for port in ports
                    }

                for future in as_completed(futures):
                    scanned_count += 1
                    progress_bar(scanned_count, total_ports)

                    try:
                        result = future.result()

                        if scan_type == "2":
                            port, status, banner, os_result = result
                            if check_os and os_type == "Not checked" and os_result != "Unknown":
                                os_type = os_result
                        else:
                            port, status, banner = result

                        if scan_type == "3":
                            if status == "OPEN":
                                open_ports.append(port)
                            elif status == "OPEN|FILTERED":
                                open_filtered_ports.append(port)
                            elif status == "FILTERED":
                                filtered_ports.append(port)
                        elif scan_type == "4":
                            if status == "OPEN":
                                open_ports.append(port)
                            elif status == "OPEN|FILTERED":
                                open_filtered_ports.append(port)
                            elif status == "CLOSED":
                                filtered_ports.append(port)
                        elif scan_type == "5":
                            if status == "OPEN":
                                open_ports.append(port)
                            elif status == "CLOSED":
                                filtered_ports.append(port)
                            elif status == "FILTERED":
                                open_filtered_ports.append(port)
                        else:
                            if status:
                                open_ports.append(port)

                        if banner:
                            banners[port] = banner

                    except socket.gaierror:
                        print(
                            Colors.RED +
                            "\n[!] Invalid IP or hostname." +
                            Colors.RESET
                        )
                        break

                    except Exception as exc:
                        with print_lock:
                            print(
                                Colors.RED +
                                f"\n[!] Scan worker error: {exc}" +
                                Colors.RESET
                            )

        except KeyboardInterrupt:
            print(
                Colors.YELLOW +
                "\n[!] Scan interrupted by user." +
                Colors.RESET
            )

        except Exception as exc:
            print(
                Colors.RED +
                f"\n[!] Error: {exc}" +
                Colors.RESET
            )

        sys.stdout.write("\n")
        sys.stdout.flush()

        if os_type == "Not checked":
            os_type = "Unknown"

        total_time = time.time() - start_time

        open_ports = sorted(set(open_ports))
        open_filtered_ports = sorted(set(open_filtered_ports))
        filtered_ports = sorted(set(filtered_ports))

        print()
        box_top()
        box_line(
            "RESULTS SUMMARY",
            text_color=Colors.NEON_CYAN + Colors.BOLD
        )
        box_divider()

        box_line(f"Target        : {target}")
        box_line(f"IP            : {ip}")
        box_line(f"OS            : {os_type}")
        box_line(f"Hostname      : {hostname}")
        box_line(f"Scan type     : {'UDP' if scan_type == '3' else 'TCP'}")
        box_line(f"Ports scanned : {total_ports}")
        box_line(
            f"Open ports    : {len(open_ports)}",
            text_color=Colors.GREEN if open_ports else Colors.RED
        )

        if scan_type in ["3", "4", "5"]:
            box_line(f"Open|Filtered : {len(open_filtered_ports)}")
            box_line(f"Filtered      : {len(filtered_ports)}")

        box_line(f"Time taken    : {total_time:.2f}s")

        if open_ports:
            box_divider()
            box_line(
                "OPEN PORTS",
                text_color=Colors.NEON_PURPLE + Colors.BOLD
            )

            for p in open_ports:
                service = (
                    get_udp_service(p)
                    if scan_type == "3"
                    else get_service(p)
                )

                label = f"{p}  {service}" if service else str(p)
                box_line(
                    f"* {label}",
                    text_color=Colors.GREEN
                )

                if p in banners:
                    box_line(
                        f"  - {banners[p]}",
                        text_color=Colors.DIM_GRAY
                    )

        if scan_type in ["3", "4", "5"] and open_filtered_ports:
            box_divider()
            box_line(
                "OPEN | FILTERED",
                text_color=Colors.YELLOW + Colors.BOLD
            )

            for p in open_filtered_ports:
                service = get_udp_service(p) if scan_type == "3" else get_service(p)
                label = f"{p}  {service}" if service else str(p)
                box_line(
                    f"* {label}",
                    text_color=Colors.YELLOW
                )

        box_bottom()

        print()
        box_top()
        box_line(
            "SAVE RESULTS?",
            text_color=Colors.NEON_CYAN + Colors.BOLD
        )
        box_divider()
        box_line(
            "Do you want to save the scan results?",
            text_color=Colors.WHITE
        )
        box_line(
            "(txt) TXT  |  (html) HTML  |  (both) TXT+HTML  |  (n) No",
            text_color=Colors.SKY_BLUE
        )
        box_bottom()

        save_choice = typed_input(
            Colors.AQUA +
            "[?] Your choice [txt-html-both-n]: " +
            Colors.RESET
        ).strip().lower()

        if save_choice in ["txt", "both"]:
            filename = save_results(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                open_filtered_ports=open_filtered_ports,
                filtered_ports=filtered_ports,
                banners=banners,
                scan_time=total_time,
                os_type=os_type,
                hostname=hostname
            )

            print(
                Colors.GREEN +
                f"\n[+] TXT File saved: {filename}" +
                Colors.RESET
            )

        if save_choice in ["html", "both"]:
            html_filename = save_results_html(
                target=target,
                open_ports=open_ports,
                banners=banners,
                scan_time=total_time,
                os_type=os_type,
                hostname=hostname,
                scan_type=scan_type
            )

            print(
                Colors.GREEN +
                f"[+] HTML File saved: {html_filename}" +
                Colors.RESET
            )

        print(
            Colors.CORNFLOWER_BLUE +
            "\n[+] Scan Finished!" +
            Colors.RESET
        )
        print(Colors.FRAME + "=" * 36 + Colors.RESET)
        print(Colors.YELLOW + "\n-xomlsx- -leon-" + Colors.RESET)
        print(Colors.BLUE + "t.me/xomlsx" + Colors.RESET)
        print(Colors.RED + "#_*" + Colors.RESET)
        print(Colors.GREEN + "CR7" + Colors.RESET)

    if scan_mode == "3":
        network = typed_input(Colors.AQUA + "[?] Enter network (For example-> 192.168.1.0/24): " + Colors.RESET).strip()
        alive_hosts = ping_sweep(network)

        if alive_hosts:
            print(Colors.GOLD + f"\n[*] Found {len(alive_hosts)} alive hosts:" + Colors.RESET)
            for ip, ttl in alive_hosts:
                print(Colors.GREEN + f"  [+] {ip} (TTL={ttl})" + Colors.RESET)
        else:
            print(Colors.RED + "[!] No alive hosts found." + Colors.RESET)

        sys.exit(0)

    if scan_mode == "4":
        domain = typed_input(Colors.AQUA + "[?] Enter domain (example.com): " + Colors.RESET).strip()

        scan_choice = typed_input(
            Colors.RED + f"[?] Start subdomain scan for {domain}? [y/n]: " + Colors.RESET).strip().lower()

        if scan_choice in ["y", "yes"]:
            found_subdomains = subdomain_scanner(domain)

            if found_subdomains:
                print(Colors.GOLD + f"\n[*] Found {len(found_subdomains)} subdomains:" + Colors.RESET)
                for subdomain, ip in found_subdomains:
                    print(Colors.GREEN + f"  [+] {subdomain} --> {ip}" + Colors.RESET)
            else:
                print(Colors.RED + "[!] No subdomains found." + Colors.RESET)
        else:
            print(Colors.DIM_GRAY + "[*] Subdomain scan skipped." + Colors.RESET)

        sys.exit(0)

    if scan_mode == "5":
        os.system("cls" if os.name == "nt" else "clear")
        os_scan_banner()
        target = typed_input(Colors.AQUA + "[?] Enter IP or Hostname: " + Colors.RESET).strip()
        os_scan_only(target)
        sys.exit(0)

    if scan_mode == "6":
        if enable_tor():
            target = typed_input(Colors.AQUA + "[?] Enter IP or Hostname: " + Colors.RESET).strip()
            ports = sorted(SERVICES.keys())
            open_ports, banners = tor_scan(target, ports, 1.0)

            print()
            box_top()
            box_line("TOR SCAN RESULTS", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line(f"Target: {target}", text_color=Colors.WHITE)
            box_line(f"Open Ports: {len(open_ports)}", text_color=Colors.GREEN if open_ports else Colors.RED)

            if open_ports:
                box_divider()
                for p in open_ports:
                    service = get_service(p)
                    banner = banners.get(p, "")
                    box_line(f"* {p} {service}", text_color=Colors.GREEN)
                    if banner:
                        box_line(f"  - {banner}", text_color=Colors.DIM_GRAY)
            box_bottom()

            save_choice = typed_input(Colors.AQUA + "\n[?] Save results? [txt/n]: " + Colors.RESET).strip().lower()

            if save_choice == "txt":
                filename = f"tor_scan_{target.replace('.', '_')}_{int(time.time())}.txt"
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("=" * 60 + "\n")
                    f.write("  TOR SCAN - RESULTS\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(f"Target      : {target}\n")
                    f.write(f"Open Ports  : {len(open_ports)}\n")
                    f.write("\n" + "-" * 60 + "\n")
                    f.write("  OPEN PORTS:\n")
                    f.write("-" * 60 + "\n")
                    for p in open_ports:
                        service = get_service(p)
                        banner = banners.get(p, "")
                        f.write(f"  Port {p:<6} {service:<15} {banner}\n")
                    f.write("\n" + "=" * 60 + "\n")
                    f.write("  t.me/xomlsx\n")
                    f.write("=" * 60 + "\n")
                print(Colors.GREEN + f"[+] File saved: {filename}" + Colors.RESET)
        sys.exit(0)

    if scan_mode == "7":
        fake = Faker()

        target = typed_input(Colors.AQUA + "[?] Enter IP or Hostname: " + Colors.RESET).strip()
        ip, hostname = resolve_target(target)

        print(Colors.GREEN + f"[*] IP: {ip}" + Colors.RESET)

        print()
        box_top()
        box_line("DECOY IP MODE", text_color=Colors.NEON_CYAN + Colors.BOLD)
        box_divider()
        box_line("1) Manual IP Input", text_color=Colors.SKY_BLUE)
        box_line("2) Auto Generate (Faker)", text_color=Colors.SKY_BLUE)
        box_bottom()

        ip_mode = typed_input(Colors.AQUA + "[?] Choose (1-2): " + Colors.RESET).strip()

        fake_ips = []

        if ip_mode == "1":
            print(Colors.AQUA + "\n[*] Enter fake IPs (empty line to finish, max 22):" + Colors.RESET)
            while len(fake_ips) < 22:
                line = input()
                if line.strip() == "":
                    break
                fake_ips.append(line.strip())

        elif ip_mode == "2":
            num_fake = typed_input(Colors.AQUA + "[?] How many fake IPs? (max 22): " + Colors.RESET).strip()
            num_fake = int(num_fake) if num_fake.isdigit() else 22
            if num_fake > 22:
                num_fake = 22
            for _ in range(num_fake):
                fake_ips.append(fake.ipv4())

        if not fake_ips:
            print(Colors.RED + "[!] No fake IPs!" + Colors.RESET)
            sys.exit(0)

        print()
        box_top()
        box_line("SELECT DECOY SPEED", text_color=Colors.NEON_CYAN + Colors.BOLD)
        box_divider()
        box_line("1) Slow ", text_color=Colors.SKY_BLUE)
        box_line("2) Normal ", text_color=Colors.SKY_BLUE)
        box_line("3) Fast ", text_color=Colors.SKY_BLUE)
        box_line("4) super Fast ", text_color=Colors.SKY_BLUE)
        box_bottom()

        speed_choice = typed_input(Colors.AQUA + "[?] Choose speed (1-4): " + Colors.RESET).strip()

        speed_settings = {
            "1": 3.0,
            "2": 1.5,
            "3": 0.5,
            "4": 0.1,
        }

        delay = speed_settings.get(speed_choice, 0.5)

        print(Colors.CYAN + f"[*] {len(fake_ips)} fake IPs loaded! Delay: {delay}s" + Colors.RESET)

        ports = sorted(SERVICES.keys())
        open_ports = []

        def decoy_scan(port):
            for fake_ip in fake_ips:
                pkt = IP(src=fake_ip, dst=ip) / TCP(dport=port, flags="S")
                sr1(pkt, timeout=0.3, verbose=0)
                time.sleep(delay)

            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=1.0, verbose=0)

            if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                rst_pkt = IP(dst=ip) / TCP(dport=port, sport=resp[TCP].dport, seq=resp[TCP].ack, ack=resp[TCP].seq + 1,
                                           flags="R")
                sr(rst_pkt, timeout=0.5, verbose=0)
                return port, True
            return port, False

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(decoy_scan, port): port for port in ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    with print_lock:
                        sys.stdout.write("\r" + " " * 120 + "\r")
                        sys.stdout.flush()
                        service = get_service(port)
                        tag = f"<{service}>" if service else ""
                        print(
                            Colors.NEON_CYAN + f"[+] Port {port} OPEN (Decoy) ---> " + Colors.GREEN + f"{tag}" + Colors.RESET)

        sys.stdout.write("\n" + " " * 120 + "\r")
        sys.stdout.flush()

        print()
        box_top()
        box_line("DECOY SCAN RESULTS", text_color=Colors.NEON_CYAN + Colors.BOLD)
        box_divider()
        box_line(f"Target: {target}", text_color=Colors.WHITE)
        box_line(f"Fake IPs: {len(fake_ips)}", text_color=Colors.GOLD)
        box_line(f"Delay: {delay}s", text_color=Colors.GOLD)
        box_line(f"Open Ports: {len(open_ports)}", text_color=Colors.GREEN if open_ports else Colors.RED)
        if open_ports:
            for p in open_ports:
                service = get_service(p)
                box_line(f"* {p} {service}", text_color=Colors.GREEN)
        box_bottom()

        sys.exit(0)


if __name__ == "__main__":
    main()