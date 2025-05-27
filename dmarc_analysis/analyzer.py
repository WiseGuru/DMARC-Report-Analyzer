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

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BLACKLIST_CACHE_FILE = 'blacklist_cache.csv'

class DMARCAnalyzer:
    def __init__(self, directory, spamhaus_domain):
        self.directory = directory
        self.spamhaus_domain = spamhaus_domain
        self.all_records = []
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']

        # Load cache threshold (days) from config
        cfg_path = os.path.join(os.path.dirname(__file__), 'config', 'config.ini')
        cfg = configparser.ConfigParser()
        cfg.read(cfg_path)
        self.cache_threshold_days = int(
            cfg.get('blacklist', 'cache_update_threshold_days', fallback='7')
        )

    @staticmethod
    def parse_dmarc_report(file_path):
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            dr = root.find('.//date_range')
            begin = dr.find('begin').text if dr is not None and dr.find('begin') is not None else None
            end = dr.find('end').text if dr is not None and dr.find('end') is not None else None
            recs = []
            for record in root.findall('.//record'):
                row = record.find('row')
                pol = row.find('policy_evaluated') if row is not None else None
                ids = record.find('identifiers')
                if row is not None and pol is not None:
                    ip = row.find('source_ip').text if row.find('source_ip') is not None else 'unknown'
                    cnt = int(row.find('count').text) if row.find('count') is not None else 0
                    sf = pol.find('spf').text if pol.find('spf') is not None else 'none'
                    dk = pol.find('dkim').text if pol.find('dkim') is not None else 'none'
                    hf = ids.find('header_from').text if ids is not None and ids.find('header_from') is not None else 'unknown'
                    ef = ids.find('envelope_from').text if ids is not None and ids.find('envelope_from') is not None else 'unknown'
                    et = ids.find('envelope_to').text if ids is not None and ids.find('envelope_to') is not None else 'unknown'
                    recs.append({
                        'source_ip': ip,
                        'count': cnt,
                        'spf_result': sf,
                        'dkim_result': dk,
                        'header_from': hf,
                        'envelope_from': ef,
                        'envelope_to': et,
                        'report_begin': begin,
                        'report_end': end,
                    })
            return recs
        except ET.ParseError:
            logging.error(f"Error parsing {file_path}")
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
                out = []
                for n in xmls:
                    with z.open(n) as f:
                        out.append(f.read())
                return out
        except Exception as e:
            logging.error(f"Error extracting {file_path}: {e}")
            return []

    def load_blacklist_cache(self):
        cache = {}
        if os.path.exists(BLACKLIST_CACHE_FILE):
            with open(BLACKLIST_CACHE_FILE, newline='') as cf:
                rd = csv.DictReader(cf)
                for r in rd:
                    ip = r['ip'].strip()
                    cache[ip] = {
                        'blacklisted': r['blacklisted'] == 'True',
                        'result_text': r['result_text'],
                        'timestamp': float(r['timestamp']),
                    }
        return cache

    def save_blacklist_cache(self, cache):
        with open(BLACKLIST_CACHE_FILE, 'w', newline='') as cf:
            wr = csv.DictWriter(cf, fieldnames=['ip', 'blacklisted', 'result_text', 'timestamp'])
            wr.writeheader()
            for ip, d in cache.items():
                wr.writerow({'ip': ip, 'blacklisted': d['blacklisted'], 'result_text': d['result_text'], 'timestamp': d['timestamp']})

    def check_blacklist(self, ip, use_cache=True, cache=None):
        ip = ip.strip()
        if use_cache and cache is not None and ip in cache:
            return cache[ip]['blacklisted'], cache[ip]['result_text']
        try:
            q = '.'.join(reversed(ip.split('.'))) + '.' + self.spamhaus_domain
            logging.info(f"Querying Spamhaus for IP: {ip}")
            ans = self.resolver.resolve(q, 'A')
            bl, rt = True, ans.rrset.to_text()
        except dns.resolver.NXDOMAIN:
            bl, rt = False, 'Not listed'
        except dns.resolver.Timeout:
            bl, rt = False, 'Timeout'
        except dns.resolver.NoNameservers as e:
            logging.error(f"DNS error for {ip}: {e}")
            bl, rt = False, 'DNS error'
        except dns.exception.DNSException as e:
            logging.error(f"General DNS error for {ip}: {e}")
            bl, rt = False, 'DNS error'
        if cache is not None:
            cache[ip] = {'blacklisted': bl, 'result_text': rt, 'timestamp': time.time()}
        return bl, rt

    @staticmethod
    def check_spf_alignment(hf, ef):
        return hf.split('@')[-1] == ef.split('@')[-1]

    @staticmethod
    def get_spf_failure_reason(ip, ef):
        try:
            r, e = spf.check2(i=ip, s=ef, h=ef.split('@')[-1])
            return f"{r}: {e}"
        except spf.SPFError as ex:
            return f"SPF error: {ex}"

    def analyze_reports(self):
        # Stage 1: collect & parse files
        logging.info(f"Scanning {self.directory} for DMARC files...")
        file_paths = []
        for root, dirs, files in os.walk(self.directory):
            for fname in files:
                if fname.endswith(('.xml', '.gz', '.zip')):
                    file_paths.append(os.path.join(root, fname))
        for fp in tqdm(file_paths, desc="Scanning DMARC files"):
            if fp.endswith('.xml'):
                self.all_records.extend(self.parse_dmarc_report(fp))
            elif fp.endswith('.gz'):
                content = self.extract_gz(fp)
                if content:
                    self.all_records.extend(self.parse_dmarc_report(BytesIO(content)))
            elif fp.endswith('.zip'):
                for content in self.extract_zip(fp):
                    if content:
                        self.all_records.extend(self.parse_dmarc_report(BytesIO(content)))
        if not self.all_records:
            logging.warning("No DMARC records found.")
            return None

        # Stage 2: DataFrame and initial stats
        df = pd.DataFrame(self.all_records)
        df_all = df.copy()
        tot = df_all['count'].sum()
        fa_spf = df_all[df_all['spf_result'] == 'fail']['count'].sum()
        fa_dkim = df_all[df_all['dkim_result'] == 'fail']['count'].sum()
        pa_spf = df_all[df_all['spf_result'] == 'pass']['count'].sum()
        pa_dkim = df_all[df_all['dkim_result'] == 'pass']['count'].sum()
        fboth = df_all[(df_all['spf_result'] == 'fail') & (df_all['dkim_result'] == 'fail')]['count'].sum()
        pboth = df_all[(df_all['spf_result'] == 'pass') & (df_all['dkim_result'] == 'pass')]['count'].sum()

        # Stage 3: filter failures
        df_fail = df_all[(df_all['spf_result'] == 'fail') | (df_all['dkim_result'] == 'fail')].copy()
        df_fail['blacklisted'] = False
        df_fail['spf_failure_reason'] = ''
        df_fail['blacklist_result_text'] = ''

        # Stage 4: build SPF failure reason cache
        unique_spf = df_fail[df_fail['spf_result'] == 'fail'][['source_ip', 'envelope_from']].drop_duplicates().values
        spf_cache = {}
        for ip, env in tqdm(unique_spf, desc="Building SPF cache"):
            key = (ip.strip(), env.strip())
            spf_cache[key] = self.get_spf_failure_reason(ip.strip(), env.strip())

        # Stage 5: blacklist checks
        cache = self.load_blacklist_cache()
        print("\nBlacklist modes: [Enter]=supplemental [a]=all")
        choice = input("Choice: ").strip().lower()
        complete = (choice == 'a')
        now_ts = time.time()
        threshold = self.cache_threshold_days * 86400
        unique_ips = [ip.strip() for ip in df_fail['source_ip'].unique()]
        if complete:
            ips_to_check = unique_ips
        else:
            ips_to_check = [ip for ip in unique_ips if ip not in cache or now_ts - cache[ip]['timestamp'] > threshold]
        print(f"Updating {len(ips_to_check)}/{len(unique_ips)} IPs")

        total_blacklisted = 0
        queried = set()
        for idx, row in tqdm(df_fail.iterrows(), total=df_fail.shape[0], desc="Checking blacklist"):
            ip = row['source_ip'].strip()
            env = row['envelope_from'].strip()
            if row['spf_result'] == 'fail':
                df_fail.at[idx, 'spf_failure_reason'] = spf_cache.get((ip, env), '')
            if ip in ips_to_check and ip not in queried:
                bl, rt = self.check_blacklist(ip, use_cache=False, cache=cache)
                queried.add(ip)
            elif ip in cache:
                bl, rt = cache[ip]['blacklisted'], cache[ip]['result_text']
            else:
                bl, rt = False, 'skipped'
            df_fail.at[idx, 'blacklist_result_text'] = rt
            if bl:
                df_fail.at[idx, 'blacklisted'] = True
                total_blacklisted += row['count']
        self.save_blacklist_cache(cache)

        # Stage 6: alignment and flags
        df_fail['spf_alignment'] = df_fail.apply(lambda x: self.check_spf_alignment(x['header_from'], x['envelope_from']), axis=1)
        df_all['spf_failure_reason'] = ''
        df_all.loc[df_fail.index, 'spf_failure_reason'] = df_fail['spf_failure_reason']
        df_all['failure_flag'] = df_all.apply(lambda x: 2 if x['spf_result']=='fail' and x['dkim_result']=='fail' else 1 if (x['spf_result']=='fail' or x['dkim_result']=='fail') else 0, axis=1)
        df_fail['failure_flag'] = df_fail.apply(lambda x: 2 if x['spf_result']=='fail' and x['dkim_result']=='fail' else 1, axis=1)

        # Stage 7: summary and CSV saving
        lost_ratio = fboth / tot if tot > 0 else 0
        summary = (
            f"Total emails: {tot}\n"
            f"Passed SPF: {pa_spf}, Passed DKIM: {pa_dkim}, Passed both: {pboth}\n"
            f"Failed SPF: {fa_spf}, Failed DKIM: {fa_dkim}, Failed both: {fboth}\n"
            f"Lost if reject: {lost_ratio:.2%}\n"
            f"Blacklisted lost: {total_blacklisted}\n"
        )
        print(summary)
        with open('summary.txt', 'w') as f:
            f.write(summary)

        df_all['report_begin_readable'] = df_all['report_begin'].apply(
            lambda x: datetime.fromtimestamp(int(x)).strftime("%Y-%m-%d %H:%M:%S")
            if pd.notnull(x) and str(x).isdigit() else "N/A"
        )
        df_all['report_end_readable'] = df_all['report_end'].apply(
            lambda x: datetime.fromtimestamp(int(x)).strftime("%Y-%m-%d %H:%M:%S")
            if pd.notnull(x) and str(x).isdigit() else "N/A"
        )
        df_all.to_csv('dmarc_report_analysis_all.csv', index=False)
        df_fail.to_csv('dmarc_report_analysis_failed.csv', index=False)

        agg_funcs = {
            'count': 'sum',
            'spf_result': lambda x: ','.join(x.unique()),
            'dkim_result': lambda x: ','.join(x.unique()),
            'blacklisted': 'max',
            'failure_flag': 'max',
        }
        agg_df = df_fail.groupby(['report_begin', 'report_end'], as_index=False).agg(agg_funcs)
        agg_df['report_begin_readable'] = agg_df['report_begin'].apply(
            lambda x: datetime.fromtimestamp(int(x)).strftime("%Y-%m-%d %H:%M:%S")
            if pd.notnull(x) and str(x).isdigit() else "N/A"
        )
        agg_df['report_end_readable'] = agg_df['report_end'].apply(
            lambda x: datetime.fromtimestamp(int(x)).strftime("%Y-%m-%d %H:%M:%S")
            if pd.notnull(x) and str(x).isdigit() else "N/A"
        )
        agg_df.to_csv('dmarc_report_analysis_aggregated.csv', index=False)

        # Optionally open CSVs
        if input('Open CSV files? (yes/no): ').strip().lower() == 'yes':
            opener = 'os.startfile' if platform.system() == 'Windows' else 'open'
            for fn in ['dmarc_report_analysis_all.csv', 'dmarc_report_analysis_failed.csv', 'dmarc_report_analysis_aggregated.csv']:
                if platform.system() == 'Windows':
                    os.startfile(fn)
                else:
                    subprocess.call([opener, fn])

        return df_fail
