from datetime import datetime
import platform
import subprocess
import xml.etree.ElementTree as ET
import pandas as pd
import os
import dns.resolver
import spf
import gzip
import zipfile
from tqdm import tqdm
import logging
from io import BytesIO
import csv
import time
import configparser
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BLACKLIST_CACHE_FILE = 'blacklist_cache.csv'

class DMARCAnalyzer:
    def __init__(self, directory, spamhaus_domain):
        self.directory = directory
        self.spamhaus_domain = spamhaus_domain
        self.all_records = []
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Use Google DNS servers

        # Load cache threshold (days) from config
        cfg_path = os.path.join(os.path.dirname(__file__), 'config', 'config.ini')
        cfg = configparser.ConfigParser()
        cfg.read(cfg_path)
        # Default cache update threshold: 28 days
        self.cache_threshold_days = int(
            cfg.get('blacklist', 'cache_update_threshold_days', fallback='28')
        )

    @staticmethod
    def parse_dmarc_report(file_source):
        """
        Parse DMARC report from an XML file or bytes.
        """
        try:
            if isinstance(file_source, (bytes, BytesIO)):
                root = ET.fromstring(file_source if isinstance(file_source, bytes) else file_source.read())
            else:
                tree = ET.parse(file_source)
                root = tree.getroot()
            dr = root.find('.//date_range')
            begin = dr.find('begin').text if dr is not None and dr.find('begin') is not None else None
            end = dr.find('end').text if dr is not None and dr.find('end') is not None else None

            records = []
            for record in root.findall('.//record'):
                row = record.find('row')
                policy = row.find('policy_evaluated') if row is not None else None
                ids = record.find('identifiers')
                auth = record.find('auth_results')

                spf_domain = (
                    auth.find('spf').find('domain').text
                    if auth is not None and auth.find('spf') is not None and auth.find('spf').find('domain') is not None
                    else 'unknown'
                )

                if row is not None and policy is not None:
                    source_ip = row.find('source_ip').text if row.find('source_ip') is not None else 'unknown'
                    count = int(row.find('count').text) if row.find('count') is not None else 0
                    spf_res = policy.find('spf').text if policy.find('spf') is not None else 'none'
                    dkim_res = policy.find('dkim').text if policy.find('dkim') is not None else 'none'
                    hdr_from = ids.find('header_from').text if ids is not None and ids.find('header_from') is not None else 'unknown'
                    env_from = ids.find('envelope_from').text if ids is not None and ids.find('envelope_from') is not None else 'unknown'
                    env_to = ids.find('envelope_to').text if ids is not None and ids.find('envelope_to') is not None else 'unknown'

                    records.append({
                        'source_ip': source_ip,
                        'count': count,
                        'spf_result': spf_res,
                        'dkim_result': dkim_res,
                        'header_from': hdr_from,
                        'envelope_from': env_from,
                        'envelope_to': env_to,
                        'spf_auth_domain': spf_domain,
                        'report_begin': begin,
                        'report_end': end
                    })
            return records
        except ET.ParseError:
            logging.error(f"Error parsing DMARC XML")
            return []

    def extract_gz(self, file_path):
        try:
            with gzip.open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logging.error(f"Error extracting {file_path}: {e}")
            return None

    def extract_zip(self, file_path):
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                xmls = [n for n in z.namelist() if n.endswith('.xml')]
                contents = []
                for name in xmls:
                    with z.open(name) as f:
                        contents.append(f.read())
                return contents
        except Exception as e:
            logging.error(f"Error extracting {file_path}: {e}")
            return []

    def load_blacklist_cache(self):
        cache = {}
        if os.path.exists(BLACKLIST_CACHE_FILE):
            with open(BLACKLIST_CACHE_FILE, newline='') as cf:
                for row in csv.DictReader(cf):
                    cache[row['ip'].strip()] = {
                        'blacklisted': row['blacklisted'] == 'True',
                        'result_text': row['result_text'],
                        'timestamp': float(row['timestamp'])
                    }
        return cache

    def save_blacklist_cache(self, cache):
        with open(BLACKLIST_CACHE_FILE, 'w', newline='') as cf:
            writer = csv.DictWriter(cf, fieldnames=['ip','blacklisted','result_text','timestamp'])
            writer.writeheader()
            for ip, data in cache.items():
                writer.writerow({
                    'ip': ip,
                    'blacklisted': data['blacklisted'],
                    'result_text': data['result_text'],
                    'timestamp': data['timestamp']
                })

    def check_blacklist(self, ip, cache=None):
        ip = ip.strip()
        if cache and ip in cache and (time.time() - cache[ip]['timestamp'] < self.cache_threshold_days*86400):
            return cache[ip]['blacklisted'], cache[ip]['result_text']
        try:
            q = '.'.join(reversed(ip.split('.'))) + '.' + self.spamhaus_domain
            ans = self.resolver.resolve(q, 'A')
            bl, res = True, ans.rrset.to_text()
        except dns.resolver.NXDOMAIN:
            bl, res = False, 'Not listed'
        except Exception as e:
            bl, res = False, str(e)
        if cache is not None:
            cache[ip] = {'blacklisted': bl, 'result_text': res, 'timestamp': time.time()}
        return bl, res

    @staticmethod
    def check_spf_alignment(header_from, envelope_from):
        return header_from.split('@')[-1] == envelope_from.split('@')[-1]

    @staticmethod
    def get_spf_failure_reason(ip, envelope_from):
        try:
            result, explanation = spf.check2(i=ip, s=envelope_from, h=envelope_from.split('@')[-1])
            return f"{result}: {explanation}"
        except Exception as e:
            return f"SPF check error: {e}"

    def analyze_reports(self):
        logging.info(f"Scanning {self.directory} for reports...")
        for root_dir, _, files in os.walk(self.directory):
            for f in files:
                p = os.path.join(root_dir, f)
                if f.endswith('.xml'):
                    self.all_records.extend(self.parse_dmarc_report(p))
                elif f.endswith('.gz'):
                    data = self.extract_gz(p)
                    if data: self.all_records.extend(self.parse_dmarc_report(data))
                elif f.endswith('.zip'):
                    for data in self.extract_zip(p):
                        self.all_records.extend(self.parse_dmarc_report(data))

        if not self.all_records:
            logging.warning("No DMARC records found.")
            return

        df = pd.DataFrame(self.all_records)

        # Prepare full DataFrame with default columns
        df['spf_failure_reason'] = ''
        df['blacklisted'] = False
        df['blacklist_result_text'] = ''
        df['spf_alignment'] = df.apply(
            lambda x: self.check_spf_alignment(x['header_from'], x['envelope_from']), axis=1)

        # Add failure_count: 0=none,1=either,2=both
        df['failure_count'] = df.apply(
            lambda x: (1 if x['spf_result']=='fail' else 0) + (1 if x['dkim_result']=='fail' else 0), axis=1)

        # Filter failures for detailed annotation
        failures = df[df['failure_count']>0].copy()
        if not failures.empty:
            # SPF failure reasons
            for idx, row in tqdm(failures.iterrows(), total=failures.shape[0], desc="Annotating failures"):
                if row['spf_result']=='fail':
                    df.at[idx, 'spf_failure_reason'] = self.get_spf_failure_reason(row['source_ip'], row['envelope_from'])

            # Blacklist with cache
            cache = self.load_blacklist_cache()
            for idx, row in tqdm(failures.iterrows(), total=failures.shape[0], desc="Checking blacklist"):
                bl, txt = self.check_blacklist(row['source_ip'], cache)
                df.at[idx, 'blacklisted'] = bl
                df.at[idx, 'blacklist_result_text'] = txt
            self.save_blacklist_cache(cache)

        # Summary
        total = df['count'].sum()
        fail_spf = df[df['spf_result']=='fail']['count'].sum()
        fail_dkim = df[df['dkim_result']=='fail']['count'].sum()
        fail_both = df[df['failure_count']==2]['count'].sum()
        ratio = fail_both/total if total>0 else 0
        lost_black = df[df['blacklisted']]['count'].sum()
        summary = (
            f"Total emails: {total}\n"
            f"Failed SPF: {fail_spf}\n"
            f"Failed DKIM: {fail_dkim}\n"
            f"Failed both: {fail_both}\n"
            f"DMARC loss ratio: {ratio:.2%}\n"
            f"Blacklisted lost: {lost_black}\n"
        )
        print(summary)
        with open('summary.txt','w') as sf: sf.write(summary)

        # Save full results including passes and failure_count
        df.to_csv('dmarc_report_analysis.csv', index=False)
        logging.info("Results with pass/fail and failure_count saved to dmarc_report_analysis.csv")

        # Aggregated failures as before
        agg_funcs = {'count':'sum','spf_result':lambda x:','.join(x.unique()),
                     'dkim_result':lambda x:','.join(x.unique()),'blacklisted':'max'}
        agg = df.groupby(['report_begin','report_end'], as_index=False).agg(agg_funcs)
        agg.to_csv('dmarc_report_analysis_aggregated.csv', index=False)
        logging.info("Aggregated failure report saved to dmarc_report_analysis_aggregated.csv")

        # Optionally open
        ans = input("Open CSV files? (yes/no):").lower().strip()
        if ans=='yes':
            files = ['dmarc_report_analysis.csv','dmarc_report_analysis_aggregated.csv']
            for f in files:
                if platform.system()=='Windows': os.startfile(f)
                elif platform.system()=='Darwin': subprocess.call(['open',f])
                else: subprocess.call(['xdg-open',f])

if __name__=='__main__':
    if len(sys.argv)!=3:
        print("Usage: python analyzer.py <reports_dir> <spamhaus_domain>")
        sys.exit(1)
    DMARCAnalyzer(sys.argv[1],sys.argv[2]).analyze_reports()
