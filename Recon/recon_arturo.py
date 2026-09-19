# recon_arturo.py — Script de reconocimiento de red interna
import subprocess
import socket
import datetime
import re

INTERFACE    = "eth0"
TARGET_NETWORK = "192.168.58.0/24"
OUTPUT_FILE  = "/home/arturo/bloque1/recon_output.txt"

# IPs de infraestructura VMware a excluir del escaneo
EXCLUDE = {"192.168.58.1", "192.168.58.254"}

def banner():
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 60)
    print("  RECON SCRIPT — TFG Ciberseguridad")
    print("  Alumno: arturo@kali")
    print(f"  Fecha:  {ts}")
    print(f"  Target: {TARGET_NETWORK}")
    print("=" * 60)
    return ts

def host_discovery():
    print(f"\n[*] Fase 1 — Descubrimiento de hosts (ARP) en {TARGET_NETWORK}")
    result = subprocess.run(
        ["arp-scan", f"--interface={INTERFACE}", TARGET_NETWORK],
        capture_output=True, text=True
    )
    # Extraer IPs y MACs del output
    hosts = []
    for line in result.stdout.splitlines():
        match = re.match(r"(192\.168\.58\.\d+)\s+([\da-f:]{17})", line)
        if match:
            ip  = match.group(1)
            mac = match.group(2)
            if ip not in EXCLUDE:
                hosts.append({"ip": ip, "mac": mac})
                print(f"[+] Host activo: {ip}  MAC: {mac}")
    print(f"\n[*] Total hosts objetivo: {len(hosts)}")
    return hosts

def port_scan(ip):
    print(f"\n[*] Fase 2 — Escaneo de puertos en {ip}")
    result = subprocess.run(
        ["nmap", "-sV", "-sC", "--top-ports", "20", "-T4", ip],
        capture_output=True, text=True
    )
    return result.stdout

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Sin registro PTR"

def main():
    ts = banner()
    hosts = host_discovery()

    with open(OUTPUT_FILE, "w") as f:
        f.write("RECON REPORT — TFG Ciberseguridad\n")
        f.write(f"Alumno: arturo | Fecha: {ts}\n")
        f.write(f"Red objetivo: {TARGET_NETWORK}\n")
        f.write("=" * 60 + "\n\n")

        for h in hosts:
            ip       = h["ip"]
            mac      = h["mac"]
            hostname = reverse_dns(ip)
            scan     = port_scan(ip)

            print(f"\n[+] {ip} | MAC: {mac} | Hostname: {hostname}")
            print(scan)

            f.write(f"Host:     {ip}\n")
            f.write(f"MAC:      {mac}\n")
            f.write(f"Hostname: {hostname}\n")
            f.write(scan)
            f.write("\n" + "-" * 40 + "\n\n")

    print(f"\n[*] Reporte guardado en {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
