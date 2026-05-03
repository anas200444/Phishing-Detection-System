import base64
import json
import time
import requests
from config import URLSCAN_HEADERS, VT_HEADERS
from url_utils import extract_domain

def check_virustotal(target_url: str) -> dict:
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(vt_endpoint, headers=VT_HEADERS, timeout=15)
        if response.status_code == 200:
            attributes = response.json().get('data', {}).get('attributes', {})
            return {
                "stats": attributes.get('last_analysis_stats', {}),
                "reputation": attributes.get('reputation', 0)
            }
        elif response.status_code == 404:
            return { "No previous scan found on VirusTotal for this  URL."}
        else:
            return {"error": f"API Error {response.status_code}: Please verify your VT API key."}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error connecting to VirusTotal: {str(e)}"}

def submit_and_poll_urlscan(target_url: str):
    urlscan_data, scan_uuid = None, None
    print("Submitting URL to urlscan.io sandbox...")
    payload = {"url": target_url, "visibility": "public"}

    try:
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=URLSCAN_HEADERS, data=json.dumps(payload), timeout=15)
        if response.status_code == 400:
            print(" urlscan.io blocked the scan ")
            return None, None
        elif response.status_code != 200:
            print(f"Error submitting to urlscan (Status {response.status_code}): {response.text}")
            return None, None

        submission_data = response.json()
        scan_uuid = submission_data.get('uuid')
        api_endpoint = submission_data.get('api')
        print("[*] Waiting for urlscan.io to process the site ")

        max_polling_attempts, polling_interval_seconds = 12, 10
        for attempt in range(max_polling_attempts):
            time.sleep(polling_interval_seconds)
            try:
                result_response = requests.get(api_endpoint, headers=URLSCAN_HEADERS, timeout=15)
                if result_response.status_code == 200:
                    return result_response.json(), scan_uuid
                elif result_response.status_code == 404:
                    print(f"     ... still processing in sandbox (attempt {attempt + 1}/{max_polling_attempts})")
                else:
                    print(f"[-] Unexpected error during polling: Status {result_response.status_code}")
                    return None, scan_uuid
            except requests.exceptions.RequestException as e:
                print(f"[-] Network error  {str(e)}")
                return None, scan_uuid
        print("[-] Timeout")
        return None, scan_uuid
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error occurred  {str(e)}")
        return None, None

def display_report(urlscan_data: dict, scan_uuid: str, vt_results: dict, target_url: str):
    target_domain = extract_domain(target_url)
    is_malicious = False
    vt_malicious_count, vt_reputation, vt_suspicious_count = 0, 0, 0
    stats = {}

    if "error" not in vt_results:
        stats = vt_results.get('stats', {})
        vt_malicious_count = stats.get('malicious', 0)
        vt_suspicious_count = stats.get('suspicious', 0)
        vt_reputation = vt_results.get('reputation', 0)
        if vt_malicious_count > 0 or vt_reputation < 0:
            is_malicious = True

    gsb_status = f"No classification for {target_domain}"
    overall_verdicts, engines_verdicts = {}, {}

    if urlscan_data:
        overall_verdicts = urlscan_data.get('verdicts', {}).get('overall', {})
        engines_verdicts = urlscan_data.get('verdicts', {}).get('engines', {})
        if overall_verdicts.get('malicious', False): is_malicious = True
        engines_malicious = engines_verdicts.get('malicious', [])
        if isinstance(engines_malicious, list) and 'googlesafebrowsing' in [str(engine).lower() for engine in engines_malicious]:
            gsb_status = f"Flagged as malicious for {target_domain}"
            is_malicious = True

    print(">>> OVERALL VERDICT: MALICIOUS <<<".center(70) if is_malicious else ">>> OVERALL VERDICT: SAFE <<<".center(70))
    print("\n[ TARGET INFORMATION ]\n")
    print(f"Target URL         : {target_url}\nTarget Domain      : {target_domain}")

    if urlscan_data:
        page_data = urlscan_data.get('page', {})
        print(f"Primary IP         : {page_data.get('ip', 'N/A')}\nHosted Country     : {page_data.get('country', 'N/A')}")
        print(f"Server Name        : {page_data.get('server', 'N/A')}\nISP / ASN          : {page_data.get('asnname', 'Unknown')} ({page_data.get('asn', 'Unknown')})\nTLS/SSL Valid      : {page_data.get('tlsValid', 'Unknown')}")
    else:
        print(" (urlscan.io scan was blocked or failed)")

    print("\n[ VIRUSTOTAL  ]\n" )
    if "error" in vt_results:
        print(f"Status             : {vt_results['error']}")
    else:
        harmless, undetected = stats.get('harmless', 0), stats.get('undetected', 0)
        total_engines = vt_malicious_count + vt_suspicious_count + harmless + undetected
        print(f"VT Verdict         : {'[ MALICIOUS ]' if (vt_malicious_count > 0 or vt_reputation < 0) else '[ CLEAN / SUSPICIOUS ONLY ]'}")
        print(f"Community Score    : {vt_reputation}\nDetection Ratio    : {vt_malicious_count} out of {total_engines} security vendors flagged the URL as Malicious")
        print(f"Breakdown          : Malicious: {vt_malicious_count} | Suspicious: {vt_suspicious_count} | Clean/Unrated: {harmless + undetected}")

    print("\n[ URLSCAN.IO THREAT I ]\n" + "-" * 70)
    if urlscan_data:
        print(f"urlscan.io Verdict : {'[ MALICIOUS ]' if overall_verdicts.get('malicious', False) else '[ CLEAN / UNKNOWN ]'}")
        print(f"Threat Score       : {overall_verdicts.get('score', 0)}\nCategories         : {', '.join(overall_verdicts.get('categories', [])) or 'None detected'}")
        print(f"Threat Tags        : {', '.join(overall_verdicts.get('tags', [])) or 'None detected'}\nGoogle Safe Browsing: {gsb_status}")
        network_lists = urlscan_data.get('lists', {})
        print("\n[ NETWORK ACTIVITY  ]\n" + "-" * 70)
        print(f"IPs Contacted      : {len(network_lists.get('ips', []))}\nDomains Reached    : {len(network_lists.get('domains', []))}\nURLs Loaded        : {len(network_lists.get('urls', []))}")
    else:
        print(f"urlscan.io Data    : Ignored / Scan Prevented\nGoogle Safe Browsing: {gsb_status} (No urlscan data)")

    if scan_uuid: print("\n[ ARTIFACTS ]\n" + "-" * 70 + f"\nScreenshot Link    : https://urlscan.io/screenshots/{scan_uuid}.png")
    print("=" * 70 + "\n")

def api_has_usable_result(vt_results: dict, urlscan_data: dict) -> bool:
    vt_ok = isinstance(vt_results, dict) and "error" not in vt_results and (bool(vt_results.get("stats")) or vt_results.get("reputation", None) is not None)
    urlscan_ok = isinstance(urlscan_data, dict) and len(urlscan_data) > 0
    return vt_ok or urlscan_ok