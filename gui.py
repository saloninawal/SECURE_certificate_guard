import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import threading
import yaml
import os
import time
import tqdm
from Levenshtein import distance
from tld import get_tld
from termcolor import colored, cprint
from confusables import unconfuse
import certstream

# Global variables
certstream_url = 'wss://certstream.calidog.io'
log_suspicious = os.path.dirname(os.path.realpath(_file)) + '/suspicious_domains' + time.strftime("%Y-%m-%d") + '.log'
suspicious_yaml = os.path.dirname(os.path.realpath(_file_)) + '/suspicious.yaml'
external_yaml = os.path.dirname(os.path.realpath(_file_)) + '/external.yaml'

class PhishingDetectorApp(tk.Tk):
    def _init_(self):
        super()._init_()
        self.title("Phishing Detector")
        self.geometry("600x400")

        # Create GUI Elements
        self.create_widgets()
        self.is_running = False

    def create_widgets(self):
        # Start Button
        self.start_button = tk.Button(self, text="Start Detection", command=self.start_detection)
        self.start_button.pack(pady=10)

        # Stop Button
        self.stop_button = tk.Button(self, text="Stop Detection", command=self.stop_detection, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        # Suspicious Domains Display
        self.suspicious_display = ScrolledText(self, width=70, height=10)
        self.suspicious_display.pack(pady=10)

        # Progress Bar
        self.progress = ttk.Progressbar(self, orient="horizontal", mode="indeterminate")
        self.progress.pack(fill=tk.X, pady=10)

    def start_detection(self):
        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start()

        # Start phishing detection in a new thread to avoid freezing the GUI
        self.thread = threading.Thread(target=self.detect_phishing)
        self.thread.start()

    def stop_detection(self):
        self.is_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()

    def log_suspicious_domain(self, domain, score):
        """Log suspicious domain in the display"""
        if score >= 75:
            color = 'red'
        elif score >= 65:
            color = 'yellow'
        else:
            color = 'green'
        self.suspicious_display.insert(tk.END, f"Suspicious: {domain} (score={score})\n", color)
        self.suspicious_display.see(tk.END)

    def detect_phishing(self):
        """Main detection method"""
        with open(suspicious_yaml, 'r') as f:
            suspicious = yaml.safe_load(f)

        with open(external_yaml, 'r') as f:
            external = yaml.safe_load(f)

        if external['override_suspicious.yaml']:
            suspicious = external
        else:
            if external['keywords'] is not None:
                suspicious['keywords'].update(external['keywords'])

            if external['tlds'] is not None:
                suspicious['tlds'].update(external['tlds'])

        def callback(message, context):
            if not self.is_running:
                return

            if message['message_type'] == "certificate_update":
                all_domains = message['data']['leaf_cert']['all_domains']
                for domain in all_domains:
                    score = self.score_domain(domain.lower(), suspicious)
                    self.log_suspicious_domain(domain, score)

                    # If issued from Let's Encrypt = more suspicious
                    if "Let's Encrypt" == message['data']['leaf_cert']['issuer']['O']:
                        score += 10

                    if score >= 100:
                        tqdm.tqdm.write(f"[!] Suspicious: {domain} (score={score})")
                    elif score >= 90:
                        tqdm.tqdm.write(f"[!] Suspicious: {domain} (score={score})")
                    elif score >= 80:
                        tqdm.tqdm.write(f"[!] Likely: {domain} (score={score})")
                    elif score >= 65:
                        tqdm.tqdm.write(f"[+] Potential: {domain} (score={score})")

                    if score >= 75:
                        with open(log_suspicious, 'a') as f:
                            f.write(f"{domain}\n")

        certstream.listen_for_events(callback, url=certstream_url)

    def score_domain(self, domain, suspicious):
        """Calculate domain score (same logic from original script)"""
        score = 0
        for t in suspicious['tlds']:
            if domain.endswith(t):
                score += 20

        if domain.startswith('*.'):
            domain = domain[2:]

        try:
            res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
            domain = '.'.join([res.subdomain, res.domain])
        except Exception:
            pass

        score += int(round(self.entropy(domain) * 10))
        domain = unconfuse(domain)
        words_in_domain = re.split("\W+", domain)

        if words_in_domain[0] in ['com', 'net', 'org']:
            score += 10

        for word in suspicious['keywords']:
            if word in domain:
                score += suspicious['keywords'][word]

        for key in [k for (k, s) in suspicious['keywords'].items() if s >= 70]:
            for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
                if distance(str(word), str(key)) == 1:
                    score += 70

        if 'xn--' not in domain and domain.count('-') >= 4:
            score += domain.count('-') * 3

        if domain.count('.') >= 3:
            score += domain.count('.') * 3

        return score

    @staticmethod
    def entropy(string):
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy


if _name_ == "_main_":
    app = PhishingDetectorApp()
    app.mainloop()
