
import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
 
 
def parse_ports(spec: str) -> list[int]:
    """Turn '22,80,8000-8100' into a sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                raise ValueError(f"Bad range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"Port out of range: {p}")
    return sorted(ports)
 
 
def grab_banner(sock: socket.socket) -> str:
    """Try to read a short greeting some services (SSH, FTP, SMTP) send."""
    try:
        sock.settimeout(1.0)
        return sock.recv(128).decode("utf-8", errors="replace").strip()
    except (socket.timeout, OSError):
        return ""
 
 
def scan_port(host: str, port: int, timeout: float, banners: bool) -> dict:
    """Scan a single port and return a result dict."""
    result = {"port": port, "state": "closed", "service": "", "banner": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((host, port))
        if code == 0:
            result["state"] = "open"
            try:
                result["service"] = socket.getservbyport(port, "tcp")
            except OSError:
                result["service"] = "unknown"
            if banners:
                result["banner"] = grab_banner(sock)
        elif code in (11, 10035):  # EAGAIN / WSAEWOULDBLOCK style timeouts
            result["state"] = "filtered"
    except socket.timeout:
        result["state"] = "filtered"
    except OSError:
        result["state"] = "error"
    finally:
        sock.close()
    return result
 
 
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Simple TCP connect port scanner (educational)."
    )
    parser.add_argument("host", help="Hostname or IP to scan (must be yours or authorized)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports, e.g. '22,80,443' or '1-1024' (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                        help="Seconds to wait per port (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("-b", "--banners", action="store_true",
                        help="Try to grab service banners from open ports")
    parser.add_argument("--json", dest="json_out", metavar="FILE",
                        help="Also save results to a JSON file")
    args = parser.parse_args()
 
    try:
        ports = parse_ports(args.ports)
        ip = socket.gethostbyname(args.host)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except socket.gaierror:
        print(f"Error: could not resolve {args.host}", file=sys.stderr)
        return 2
 
    print(f"Scanning {args.host} ({ip}), {len(ports)} ports. "
          f"Only scan systems you have permission to test.\n")
 
    start = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(scan_port, ip, p, args.timeout, args.banners) for p in ports]
        for fut in as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: r["port"])
 
    open_ports = [r for r in results if r["state"] == "open"]
    if open_ports:
        print(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<14}BANNER")
        for r in open_ports:
            banner = r["banner"].splitlines()[0][:50] if r["banner"] else ""
            print(f"{r['port']:<8}{r['state']:<8}{r['service']:<14}{banner}")
    else:
        print("No open ports found.")
 
    filtered = sum(1 for r in results if r["state"] == "filtered")
    print(f"\nDone in {time.time() - start:.2f}s: "
          f"{len(open_ports)} open, {filtered} filtered, "
          f"{len(results) - len(open_ports) - filtered} closed/error.")
 
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"host": args.host, "ip": ip, "results": results}, f, indent=2)
        print(f"Saved results to {args.json_out}")
    return 0
 
 
if __name__ == "__main__":
    sys.exit(main())