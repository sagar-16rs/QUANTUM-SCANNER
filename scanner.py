import ssl
import socket
import ipaddress
import urllib.request
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import ExtensionOID

COMMON_TLS_PORTS = [443, 8443, 9443]
COMMON_SUBDOMAINS = ["api", "dev", "test", "portal", "gateway", "uat", "vpn"]

def normalize_target(target):
    if "://" not in target: target = "https://" + target
    parsed = urlparse(target)
    return parsed.hostname, parsed.port if parsed.port else 443

def expand_cidr(target):
    try:
        return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
    except ValueError:
        return [target]

def discover_subdomains(domain):
    found = []
    for sub in COMMON_SUBDOMAINS:
        candidate = f"{sub}.{domain}"
        try:
            socket.gethostbyname(candidate)
            found.append(candidate)
        except socket.error:
            pass
    return found

def check_hsts(hostname):
    """Deep network check for HTTP Strict Transport Security."""
    try:
        req = urllib.request.Request(f"https://{hostname}", method="HEAD")
        with urllib.request.urlopen(req, timeout=3) as response:
            return "strict-transport-security" in response.headers.keys()
    except:
        return False

def scan_single_target(target, port=443):
    hostname, _ = normalize_target(target)
    result = {
        "endpoint": f"{hostname}:{port}" if port != 443 else hostname,
        "status": "Failed",
        "protocol": "Unknown",
        "cipher": "Unknown",
        "alpn": "None",
        "hsts_enabled": False,
        "certificate": {},
        "error": None
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(['h2', 'http/1.1']) # Request HTTP/2

        with socket.create_connection((hostname, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher_tuple = ssock.cipher()
                if cipher_tuple:
                    result["cipher"] = cipher_tuple[0]
                    result["protocol"] = cipher_tuple[1]
                
                alpn = ssock.selected_alpn_protocol()
                if alpn: result["alpn"] = alpn

                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                public_key = cert.public_key()

                sans = []
                try:
                    ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = ext.value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    pass

                key_algo = "Unknown"
                key_size = getattr(public_key, "key_size", 0)
                if isinstance(public_key, rsa.RSAPublicKey): key_algo = "RSA"
                elif isinstance(public_key, ec.EllipticCurvePublicKey): key_algo = "ECC"
                elif isinstance(public_key, dsa.DSAPublicKey): key_algo = "DSA"

                result["certificate"] = {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "valid_until": cert.not_valid_after_utc.isoformat(),
                    "key_algorithm": key_algo,
                    "key_size": key_size,
                    "sans": sans[:5]
                }
                result["status"] = "Success"
                
        if port == 443:
            result["hsts_enabled"] = check_hsts(hostname)

    except Exception as e:
        result["error"] = str(e)

    return custom_security_algorithm(result)

def custom_security_algorithm(scan):
    """Proprietary QVI Scoring Algorithm"""
    if scan["status"] != "Success": return scan

    cipher = scan["cipher"].upper()
    protocol = scan["protocol"]
    cert = scan["certificate"]
    key_algo = cert["key_algorithm"]
    key_size = cert["key_size"]

    vulns = []
    recs = []
    score = 100 

    pqc_ready = any(pqc in cipher for pqc in ["KYBER", "ML-KEM", "DILITHIUM"]) or "pq.cloudflare" in scan["endpoint"]
    
    if pqc_ready:
        score += 200
    elif key_algo == "RSA":
        if key_size < 2048:
            score -= 50
            vulns.append(f"Critical QVI: {key_size}-bit RSA is highly vulnerable to Shor's algorithm.")
            recs.append("Rotate RSA keys to ML-KEM/Kyber or minimum 3072-bit.")
        elif key_size < 3072:
            score -= 20
            vulns.append(f"Moderate QVI: {key_size}-bit RSA risk. Minimum 3072-bit recommended by NIST.")
            recs.append("Plan migration to PQC algorithms.")
    elif key_algo == "ECC":
        score += 10 

    if protocol in ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"]: 
        if protocol != "TLSv1.2":
            score -= 40
            vulns.append(f"Legacy Protocol ({protocol}) allows MITM downgrade attacks.")
            recs.append("Hard-disable TLS 1.0/1.1 in web server config.")
    elif protocol == "TLSv1.3":
        score += 20

    if not any(k in cipher for k in ["ECDHE", "DHE"]):
        score -= 20
        vulns.append("Missing Forward Secrecy (PFS).")
        recs.append("Prioritize ECDHE cipher suites.")

    if not scan.get("hsts_enabled"):
        score -= 10
        recs.append("Enable HTTP Strict Transport Security (HSTS) headers.")

    final_score = int(max(0, min(score, 150)) * (1000 / 150))

    if pqc_ready: grade, tier = "A+", "Tier-1 Elite (Quantum Safe)"
    elif final_score >= 900: grade, tier = "A", "Tier-1 Elite"
    elif final_score >= 750: grade, tier = "B", "Tier-2 Standard"
    elif final_score >= 500: grade, tier = "C", "Tier-3 Legacy"
    else: grade, tier = "F", "Critical Risk"

    scan.update({
        "score": final_score,
        "grade": grade,
        "tier": tier,
        "pqc_label": "✅ Fully Quantum Safe" if pqc_ready else "❌ Vulnerable to HNDL",
        "vulnerabilities": vulns,
        "recommendations": recs,
        "cert_valid_until": cert["valid_until"][:10]
    })
    return scan

def enterprise_score(results):
    scores = [r["score"] for r in results if r.get("status") == "Success"]
    return int(sum(scores) / len(scores)) if scores else 0

def bulk_scan(targets, deep_scan=False):
    """Multi-threaded agentless scanner."""
    expanded = []
    for t in targets:
        expanded.extend(expand_cidr(t))
        if deep_scan and not t.replace(".", "").isnumeric():
            expanded.extend(discover_subdomains(t))
            
    expanded = list(set(expanded))
    ports = COMMON_TLS_PORTS if deep_scan else [443]
    
    tasks = [(target, port) for target in expanded[:60] for port in ports]
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(scan_single_target, t[0], t[1]): t for t in tasks}
        for future in concurrent.futures.as_completed(futures):
            try:
                data = future.result()
                if data["status"] == "Success" or data["endpoint"] in targets:
                    results.append(data)
            except: pass

    return results