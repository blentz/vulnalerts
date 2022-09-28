import os
import requests
import time
import random
from datetime import datetime

headers = {
    'Authorization': 'Bearer ' + os.getenv('API_KEY'),
    'Content-Type': 'application/json'
}
yesterday = datetime.now().replace(day=datetime.now().day-1,
                                    hour=0,
                                    minute=0,
                                    second=0,
                                    microsecond=0)


def get_cpes():
    print("reading product list...")
    cpe_names = set()
    cpe_lines = None
    with open('cpe.txt', 'r') as v:
        cpe_lines = v.readlines()
    for line in cpe_lines:
        cpe_names.add(line.strip())
    return list(cpe_names)


def get_cpe_names(search_str="", retries=0):
    print("fetching product list: %s" % search_str)
    url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
    response = requests.get(url,
                            {'cpeMatchString': search_str}.update(headers))
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        if exc.errno == 403 and retries <= 4:
            time.sleep(random.randint(10, 30))
            return get_cpe_names(search_str, retries=retries+1)
        print(exc)
        return []
    ret = set()
    for item in response.json()['products']:
        if item['cpe']['deprecated'] != 'True':
            ret.add(item['cpe']['cpeName'])
    print("Found Products: %s" % ret)
    return list(ret)


def get_nvd_feed(cpeName):
    print("fetching cve feed: %s" % cpeName)
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'   # NVD Feed URL

    response = requests.get(url, {'cpeName': cpeName,
                                  'pubStartDate': yesterday.isoformat(),
                                  'pubEndDate': datetime.now().isoformat(),
                                  'isVulnerable': True
                                 }.update(headers))
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        print(exc)
        return {}
    return response.json()


def parse_nvd_feed(cpes):
    print("scanning %i product feeds..." % len(cpes))
    json_responses = {}
    for cpe in cpes:
        json_responses[cpe] = get_nvd_feed(cpe.strip())
        time.sleep(random.randint(3, 10))
    cve_count = 0
    message = ""

    for cpe, cve_feed in json_responses.items():
        for vuln in cve_feed.get('vulnerabilities', []):
            if 'configurations'in vuln['cve'].keys():
                product = vuln['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0]['criteria'].split(":")[3]
                cpe_product = cpe.split(":")[3]
                if product != cpe_product:
                    continue

            if datetime.fromisoformat(vuln['cve']['published']) <= yesterday:
                continue

            cve_id = vuln['cve']['id']
            description = ""
            for desc in vuln['cve']['descriptions']:
                if desc['lang'] == 'en':
                    description += desc['value']
            severity = ""
            if vuln['cve']['metrics']:
                cvssData = vuln['cve']['metrics']['cvssMetricV2'][0]['cvssData']
                severity = "Severity: {} | Vector: {} | Complexity: {} | ".format(cvssData['baseSeverity'],
                                                                               cvssData['accessVector'],
                                                                               cvssData['accessComplexity'])
                severity += "Auth: {} | Confidence Impact: {} | Integrity Impact: {} | Availability Impact: {}): ".format(cvssData['authentication'],
                                                                                                                           cvssData['confidentialityImpact'],
                                                                                                                           cvssData['integrityImpact'],
                                                                                                                           cvssData['availabilityImpact'])
                message = message + slack_block_format(cpe, description, cve_id, severity)
            cve_count = cve_count + 1
    return message, cve_count


def slack_block_format(product, description, cve_id, severity):
    block = ',{"type": "section", "text": {"type": "mrkdwn","text": "*Product:* ' + \
            product + \
            '\n *CVE ID:* ' + \
            cve_id + \
            '\n *Description:* ' + \
            description + \
            '\n *Severity:* ' + \
            severity+ \
            '\n "}}, {"type": "divider"}'
    return block


def send_slack_alert(message, cve_count):
    url = os.getenv('SLACK_WEBHOOK')
    slack_message = '{"blocks": [{"type": "section","text": {"type": "plain_text","emoji": true,"text": "Hello :wave:, ' + \
            str(cve_count) + \
            ' Security Vulnerabilities affecting your Tech Stack were disclosed today."}}' + \
            message + \
            ']}'
    requests.post(url, data=slack_message)


if __name__ == '__main__':
    print("VulnAlerts Using GitHub Actions\n")
    message, cve_count = parse_nvd_feed(get_cpes())
    send_slack_alert(message, cve_count)
    print("Notification Sent")
