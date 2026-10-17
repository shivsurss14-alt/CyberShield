"""
CyberShield - Personal Cyber Security Suite  (Python + MySQL + Tkinter)

Screen flow:
  1. Master password screen (first run: create it; 3 wrong attempts -> program exits)
  2. Welcome screen  3. Info screen (+ I Agree)  4. Loading screen  5. Final screen (+ Start)  6. Dashboard

Modules:
  1. Phishing URL Detector     - rule-based risk score for a URL (the link is NEVER opened)
  2. File Integrity Monitor    - SHA-256 baseline of files, detects TAMPERED / MISSING files
  3. Login Attack Monitor      - demo login portal, detects brute-force (3+ failed logins in 5 minutes)
  4. Dashboard + Alerts        - counters, bar chart and latest alerts, all saved in MySQL

Setup:
    pip install mysql-connector-python pillow
    Keep the "screens" folder (background images) next to this file.
    Change DB_CONFIG below (user / password), then run:  python cybershield.py
    (XAMPP default: user "root", password "")

Note: this is a learning/demo tool. It is rule-based, so it can have false positives/negatives.
"""
import hashlib
import hmac
import ipaddress
import os
import random
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog
from urllib.parse import urlparse

try:
    import mysql.connector
    from PIL import Image, ImageTk
except ImportError as e:
    print("Missing package:", e)
    print("Run:  pip install mysql-connector-python pillow")
    raise SystemExit(1)

DB_CONFIG = {"host": "localhost", "user": "root", "password": ""}
DB_NAME = "cybershield_db"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEMO_USER, DEMO_PASS = "admin", "Admin@123"   # demo login portal account
BRUTE_LIMIT = 3                               # failed logins within 5 minutes -> alert

GREEN, ORANGE, RED, GRAY = "#0a7d2c", "#b26a00", "#b3261e", "#6b7280"
NAVY, TEAL = "#0B1220", "#22D3EE"
ACCENT, FIELD, WHITE = "#34D399", "#16213A", "#F1F5F9"
SCREENS_DIR = os.path.join(BASE_DIR, "screens")
WIN_W, WIN_H = 1000, 650   # intro screens size
MAX_ATTEMPTS = 3          # wrong master password attempts before the program exits


# ---------------------------- Database layer ----------------------------
def get_conn():
    return mysql.connector.connect(database=DB_NAME, **DB_CONFIG)


def init_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    cur.execute(f"USE {DB_NAME}")
    cur.execute("""CREATE TABLE IF NOT EXISTS url_checks (
                       id INT AUTO_INCREMENT PRIMARY KEY,
                       ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       url VARCHAR(500) NOT NULL,
                       score INT NOT NULL,
                       verdict VARCHAR(12) NOT NULL,
                       reasons VARCHAR(500))""")
    cur.execute("""CREATE TABLE IF NOT EXISTS file_baseline (
                       id INT AUTO_INCREMENT PRIMARY KEY,
                       path VARCHAR(500) NOT NULL,
                       sha256 CHAR(64) NOT NULL,
                       ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS login_log (
                       id INT AUTO_INCREMENT PRIMARY KEY,
                       ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       username VARCHAR(50),
                       success TINYINT(1) NOT NULL)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS alerts (
                       id INT AUTO_INCREMENT PRIMARY KEY,
                       ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       type VARCHAR(20) NOT NULL,
                       details VARCHAR(300))""")
    cur.execute("""CREATE TABLE IF NOT EXISTS app_meta (
                       id INT PRIMARY KEY,
                       salt VARBINARY(16) NOT NULL,
                       pw_hash CHAR(64) NOT NULL)""")
    conn.commit()
    conn.close()


def run(query, params=(), fetch=False):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(query, params)
    rows = cur.fetchall() if fetch else None
    conn.commit()
    conn.close()
    return rows


def add_alert(kind, details):
    """Insert an alert unless the same alert was already raised in the last minute."""
    details = details[:300]
    dup = run("SELECT COUNT(*) FROM alerts WHERE type=%s AND details=%s AND ts >= NOW() - INTERVAL 1 MINUTE",
              (kind, details), fetch=True)[0][0]
    if not dup:
        run("INSERT INTO alerts (type, details) VALUES (%s,%s)", (kind, details))


# ---------------------------- Security logic ----------------------------
SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "bank", "password",
                    "confirm", "free", "gift", "prize", "otp", "kyc"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"]
BAD_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click")


def analyze_url(url):
    """Return (score 0-100, verdict, reasons). The URL is only analysed as text, never opened."""
    url = url.strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    low = url.lower()
    score, reasons = 0, []

    if not low.startswith("https://"):
        score += 20
        reasons.append("Not using HTTPS (+20)")
    try:
        ipaddress.ip_address(host)
        score += 30
        reasons.append("Uses an IP address instead of a domain name (+30)")
    except ValueError:
        pass
    if "@" in url:
        score += 25
        reasons.append("Contains '@' symbol, can hide the real destination (+25)")
    found = [w for w in SUSPICIOUS_WORDS if w in low]
    if found:
        pts = min(len(found) * 10, 40)
        score += pts
        reasons.append(f"Suspicious words: {', '.join(found)} (+{pts})")
    if len(url) > 75:
        score += 15
        reasons.append("Very long URL (+15)")
    if any(host == s or host.endswith("." + s) for s in SHORTENERS):
        score += 20
        reasons.append("Shortened link hides the real destination (+20)")
    if host.count("-") >= 3:
        score += 10
        reasons.append("Many hyphens in the domain name (+10)")
    if host.count(".") >= 4:
        score += 10
        reasons.append("Too many sub-domains (+10)")
    if "xn--" in host:
        score += 20
        reasons.append("Punycode domain, can imitate real sites (+20)")
    if host.endswith(BAD_TLDS):
        score += 15
        reasons.append("Domain ending often abused in scams (+15)")

    score = min(score, 100)
    verdict = "SAFE" if score < 25 else "SUSPICIOUS" if score < 55 else "DANGEROUS"
    if not reasons:
        reasons.append("No risk indicators found")
    return score, verdict, reasons


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


SAMPLE_URLS = [
    "https://www.google.com",
    "http://secure-paypal-login.example.com",
    "http://192.168.1.5/verify-login@bank.com",
    "http://bit.ly/free-gift-claim",
    "https://github.com/login",
]


# ------------------------------- GUI layer -------------------------------
class Dashboard(ttk.Frame):
    """Main dashboard (shown after the 5 intro screens)."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app

        header = tk.Frame(self, bg=NAVY)
        header.pack(fill="x")
        tk.Label(header, text="CyberShield", font=("Arial", 22, "bold"), fg="white", bg=NAVY).pack(side="left", padx=16, pady=8)
        tk.Label(header, text="Personal Cyber Security Suite  |  Phishing  -  File Integrity  -  Login Attacks",
                 font=("Arial", 11), fg=TEAL, bg=NAVY).pack(side="left", pady=8)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.t_dash, self.t_url, self.t_files, self.t_login, self.t_alerts = (ttk.Frame(self.nb) for _ in range(5))
        for tab, name in ((self.t_dash, "  Dashboard  "), (self.t_url, "  Phishing Detector  "),
                          (self.t_files, "  File Integrity  "), (self.t_login, "  Login Monitor  "),
                          (self.t_alerts, "  Alerts  ")):
            self.nb.add(tab, text=name)
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.refresh_all())

        self.build_dashboard()
        self.build_url()
        self.build_files()
        self.build_login()
        self.build_alerts()
        self.refresh_all()

    # ======================= Dashboard =======================
    def build_dashboard(self):
        cards = ttk.Frame(self.t_dash)
        cards.pack(fill="x", padx=10, pady=12)
        self.card_vars = {}
        for i, (key, title, color) in enumerate((("urls", "URLs Checked", GRAY), ("PHISHING", "Phishing Alerts", ORANGE),
                                                 ("FILE", "File Alerts", RED), ("BRUTE_FORCE", "Brute-force Alerts", RED))):
            box = tk.Frame(cards, bg="white", highlightbackground="#cbd5e1", highlightthickness=1)
            box.grid(row=0, column=i, padx=8, sticky="nsew")
            cards.columnconfigure(i, weight=1)
            v = tk.StringVar(value="0")
            self.card_vars[key] = v
            tk.Label(box, textvariable=v, font=("Arial", 30, "bold"), fg=color, bg="white").pack(pady=(10, 0))
            tk.Label(box, text=title, font=("Arial", 11), fg="#334155", bg="white").pack(pady=(0, 10))

        ttk.Label(self.t_dash, text="Alerts by type", font=("Arial", 12, "bold")).pack(anchor="w", padx=14)
        self.chart = tk.Canvas(self.t_dash, height=190, bg="white", highlightbackground="#cbd5e1", highlightthickness=1)
        self.chart.pack(fill="x", padx=14, pady=6)

        ttk.Label(self.t_dash, text="Latest alerts", font=("Arial", 12, "bold")).pack(anchor="w", padx=14, pady=(8, 0))
        self.dash_tree = self.make_alert_tree(self.t_dash, height=7)

    def make_alert_tree(self, parent, height):
        cols = ("time", "type", "details")
        tree = ttk.Treeview(parent, columns=cols, show="headings", height=height)
        for c, w in zip(cols, (160, 120, 680)):
            tree.heading(c, text=c.title())
            tree.column(c, width=w)
        tree.tag_configure("PHISHING", foreground=ORANGE)
        tree.tag_configure("FILE", foreground=RED)
        tree.tag_configure("BRUTE_FORCE", foreground=RED)
        tree.pack(fill="both", expand=True, padx=14, pady=6)
        return tree

    def refresh_dashboard(self):
        counts = dict(run("SELECT type, COUNT(*) FROM alerts GROUP BY type", fetch=True))
        self.card_vars["urls"].set(str(run("SELECT COUNT(*) FROM url_checks", fetch=True)[0][0]))
        for k in ("PHISHING", "FILE", "BRUTE_FORCE"):
            self.card_vars[k].set(str(counts.get(k, 0)))
        # bar chart drawn on a canvas
        self.chart.delete("all")
        data = [("Phishing", counts.get("PHISHING", 0), ORANGE), ("File tampering", counts.get("FILE", 0), RED),
                ("Brute-force", counts.get("BRUTE_FORCE", 0), "#7c3aed")]
        top = max([d[1] for d in data] + [1])
        for i, (name, val, color) in enumerate(data):
            x0 = 120 + i * 260
            h = int(val / top * 120)
            self.chart.create_rectangle(x0, 150 - h, x0 + 100, 150, fill=color, outline="")
            self.chart.create_text(x0 + 50, 142 - h, text=str(val), font=("Arial", 12, "bold"))
            self.chart.create_text(x0 + 50, 168, text=name, font=("Arial", 11))
        self.fill_alert_tree(self.dash_tree, 7)

    def fill_alert_tree(self, tree, limit):
        rows = run("SELECT ts, type, details FROM alerts ORDER BY id DESC LIMIT %s", (limit,), fetch=True)
        tree.delete(*tree.get_children())
        for ts, kind, details in rows:
            tree.insert("", "end", values=(ts, kind, details), tags=(kind,))

    # ======================= Phishing Detector =======================
    def build_url(self):
        f = ttk.LabelFrame(self.t_url, text="Check a URL (the link is analysed as text only, never opened)")
        f.pack(fill="x", padx=10, pady=10)
        self.u_var = tk.StringVar()
        ttk.Label(f, text="URL").grid(row=0, column=0, padx=6, pady=8)
        e = ttk.Entry(f, textvariable=self.u_var, width=78)
        e.grid(row=0, column=1, padx=4)
        e.bind("<Return>", lambda ev: self.check_url())
        ttk.Button(f, text="Analyze", command=self.check_url).grid(row=0, column=2, padx=8)
        ttk.Label(f, text="Samples").grid(row=1, column=0, padx=6, pady=4)
        cb = ttk.Combobox(f, values=SAMPLE_URLS, width=76, state="readonly")
        cb.grid(row=1, column=1, padx=4, sticky="w")
        cb.bind("<<ComboboxSelected>>", lambda ev: self.u_var.set(cb.get()))

        self.u_result = tk.Label(self.t_url, text="Result appears here", font=("Arial", 24, "bold"), fg=GRAY)
        self.u_result.pack(pady=(10, 2))
        self.u_bar = ttk.Progressbar(self.t_url, length=420, maximum=100)
        self.u_bar.pack()
        self.u_reasons = tk.Text(self.t_url, height=6, width=100, font=("Arial", 11), state="disabled", bg="#f8fafc")
        self.u_reasons.pack(padx=10, pady=8)

        top = ttk.Frame(self.t_url)
        top.pack(fill="x", padx=10)
        ttk.Label(top, text="History", font=("Arial", 12, "bold")).pack(side="left")
        ttk.Button(top, text="Clear History", command=self.clear_urls).pack(side="right")
        cols = ("time", "url", "score", "verdict")
        self.u_tree = ttk.Treeview(self.t_url, columns=cols, show="headings", height=7)
        for c, w in zip(cols, (150, 560, 70, 110)):
            self.u_tree.heading(c, text=c.title())
            self.u_tree.column(c, width=w)
        for tag, col in (("SAFE", GREEN), ("SUSPICIOUS", ORANGE), ("DANGEROUS", RED)):
            self.u_tree.tag_configure(tag, foreground=col)
        self.u_tree.pack(fill="both", expand=True, padx=10, pady=6)

    def check_url(self):
        url = self.u_var.get().strip()
        if not url:
            return messagebox.showinfo("Enter URL", "Type or paste a URL first.")
        score, verdict, reasons = analyze_url(url)
        run("INSERT INTO url_checks (url, score, verdict, reasons) VALUES (%s,%s,%s,%s)",
            (url[:500], score, verdict, "; ".join(reasons)[:500]))
        if verdict != "SAFE":
            add_alert("PHISHING", f"{verdict} ({score}/100): {url}")
        color = {"SAFE": GREEN, "SUSPICIOUS": ORANGE, "DANGEROUS": RED}[verdict]
        self.u_result.config(text=f"{verdict}   ({score}/100)", fg=color)
        self.u_bar["value"] = score
        self.u_reasons.config(state="normal")
        self.u_reasons.delete("1.0", "end")
        self.u_reasons.insert("1.0", "\n".join("- " + r for r in reasons) +
                              "\n\nNote: rule-based check. SAFE does not guarantee a site is trustworthy.")
        self.u_reasons.config(state="disabled")
        self.refresh_urls()

    def refresh_urls(self):
        rows = run("SELECT ts, url, score, verdict FROM url_checks ORDER BY id DESC LIMIT 100", fetch=True)
        self.u_tree.delete(*self.u_tree.get_children())
        for r in rows:
            self.u_tree.insert("", "end", values=r, tags=(r[3],))

    def clear_urls(self):
        if messagebox.askyesno("Confirm", "Delete the URL check history?"):
            run("DELETE FROM url_checks")
            self.refresh_urls()

    # ======================= File Integrity Monitor =======================
    def build_files(self):
        top = ttk.Frame(self.t_files)
        top.pack(fill="x", padx=10, pady=10)
        for text, cmd in (("Add File to Baseline", self.add_file), ("Create Demo File", self.create_demo),
                          ("Scan All Files", self.scan_files), ("Remove Selected", self.remove_file)):
            ttk.Button(top, text=text, command=cmd).pack(side="left", padx=4)
        self.f_status = ttk.Label(self.t_files, text="Add a file, then click Scan. A changed file shows TAMPERED.",
                                  font=("Arial", 11))
        self.f_status.pack(anchor="w", padx=14)
        cols = ("path", "baseline hash (SHA-256)", "status", "last scan")
        self.f_tree = ttk.Treeview(self.t_files, columns=cols, show="headings", height=14)
        for c, w in zip(cols, (460, 240, 110, 100)):
            self.f_tree.heading(c, text=c.title())
            self.f_tree.column(c, width=w)
        for tag, col in (("OK", GREEN), ("TAMPERED", RED), ("MISSING", ORANGE), ("NEW", GRAY)):
            self.f_tree.tag_configure(tag, foreground=col)
        self.f_tree.pack(fill="both", expand=True, padx=14, pady=8)
        self.f_map = {}
        self.load_baselines()

    def load_baselines(self):
        self.f_tree.delete(*self.f_tree.get_children())
        self.f_map = {}
        for fid, path, h in run("SELECT id, path, sha256 FROM file_baseline ORDER BY id", fetch=True):
            iid = self.f_tree.insert("", "end", values=(path, h[:32] + "...", "Not scanned", ""), tags=("NEW",))
            self.f_map[iid] = (fid, path, h)

    def add_file(self, path=None):
        path = path or filedialog.askopenfilename(title="Select a file to protect")
        if not path:
            return
        try:
            h = sha256_file(path)
        except OSError as e:
            return messagebox.showerror("Error", f"Cannot read the file:\n{e}")
        existing = run("SELECT id FROM file_baseline WHERE path=%s", (path,), fetch=True)
        if existing:
            run("UPDATE file_baseline SET sha256=%s, ts=NOW() WHERE id=%s", (h, existing[0][0]))
        else:
            run("INSERT INTO file_baseline (path, sha256) VALUES (%s,%s)", (path, h))
        self.load_baselines()

    def create_demo(self):
        path = os.path.join(BASE_DIR, "cybershield_demo.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("Salary report: pay 500 to Ravi\n")
        self.add_file(path)
        messagebox.showinfo("Demo file created",
                            f"Created and added to baseline:\n{path}\n\nNow open it in Notepad, change the text, "
                            "save it, then click 'Scan All Files'.")

    def scan_files(self):
        if not self.f_map:
            return messagebox.showinfo("No files", "Add at least one file to the baseline first.")
        now = datetime.now().strftime("%H:%M:%S")
        counts = {"OK": 0, "TAMPERED": 0, "MISSING": 0}
        for iid, (fid, path, h) in self.f_map.items():
            try:
                status = "OK" if sha256_file(path) == h else "TAMPERED"
            except OSError:
                status = "MISSING"
            counts[status] += 1
            self.f_tree.item(iid, values=(path, h[:32] + "...", status, now), tags=(status,))
            if status != "OK":
                add_alert("FILE", f"{status}: {path}")
        self.f_status.config(text=f"Scan complete at {now}:  {counts['OK']} OK,  "
                                  f"{counts['TAMPERED']} tampered,  {counts['MISSING']} missing")
        self.refresh_dashboard()

    def remove_file(self):
        sel = self.f_tree.selection()
        if not sel:
            return messagebox.showinfo("Select", "Select a file row first.")
        if messagebox.askyesno("Confirm", "Remove this file from the baseline?"):
            run("DELETE FROM file_baseline WHERE id=%s", (self.f_map[sel[0]][0],))
            self.load_baselines()

    # ======================= Login Attack Monitor =======================
    def build_login(self):
        left = ttk.LabelFrame(self.t_login, text="Demo login portal")
        left.pack(side="left", fill="y", padx=10, pady=10)
        self.l_user, self.l_pass = tk.StringVar(value=DEMO_USER), tk.StringVar()
        ttk.Label(left, text="Username").pack(padx=14, pady=(14, 2), anchor="w")
        ttk.Entry(left, textvariable=self.l_user, width=24).pack(padx=14)
        ttk.Label(left, text="Password").pack(padx=14, pady=(10, 2), anchor="w")
        pe = ttk.Entry(left, textvariable=self.l_pass, show="*", width=24)
        pe.pack(padx=14)
        pe.bind("<Return>", lambda ev: self.try_login())
        ttk.Button(left, text="Login", command=self.try_login).pack(pady=12)
        ttk.Button(left, text="Simulate Attack (10 fails)", command=self.simulate_attack).pack(pady=4)
        ttk.Button(left, text="Clear Login Log", command=self.clear_login_log).pack(pady=4)
        self.l_result = tk.Label(left, text="", font=("Arial", 12, "bold"), wraplength=200)
        self.l_result.pack(padx=10, pady=10)
        ttk.Label(left, text=f"Demo account:\n{DEMO_USER} / {DEMO_PASS}\n\nRule: {BRUTE_LIMIT}+ failed logins\nin 5 minutes = alert\n"
                             "(passwords are never\nstored in the log)", foreground="gray").pack(padx=10, pady=8)

        right = ttk.Frame(self.t_login)
        right.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=10)
        ttk.Label(right, text="Login attempts log", font=("Arial", 12, "bold")).pack(anchor="w")
        cols = ("time", "username", "result")
        self.l_tree = ttk.Treeview(right, columns=cols, show="headings", height=18)
        for c, w in zip(cols, (180, 160, 120)):
            self.l_tree.heading(c, text=c.title())
            self.l_tree.column(c, width=w)
        self.l_tree.tag_configure("OK", foreground=GREEN)
        self.l_tree.tag_configure("FAIL", foreground=RED)
        self.l_tree.pack(fill="both", expand=True, pady=6)

    def try_login(self):
        user = self.l_user.get().strip()
        ok = user == DEMO_USER and self.l_pass.get() == DEMO_PASS
        run("INSERT INTO login_log (username, success) VALUES (%s,%s)", (user[:50], 1 if ok else 0))
        self.l_pass.set("")
        if ok:
            self.l_result.config(text="Login successful", fg=GREEN)
        else:
            self.l_result.config(text="Login failed", fg=RED)
            self.check_bruteforce(user)
        self.refresh_login()

    def check_bruteforce(self, user):
        fails = run("SELECT COUNT(*) FROM login_log WHERE username=%s AND success=0 "
                    "AND ts >= NOW() - INTERVAL 5 MINUTE", (user[:50],), fetch=True)[0][0]
        if fails >= BRUTE_LIMIT:
            recent = run("SELECT COUNT(*) FROM alerts WHERE type='BRUTE_FORCE' AND details LIKE %s "
                         "AND ts >= NOW() - INTERVAL 5 MINUTE", (f"%'{user}'%",), fetch=True)[0][0]
            if not recent:
                add_alert("BRUTE_FORCE", f"Brute-force suspected: {fails} failed logins for user '{user}' within 5 minutes")
                messagebox.showwarning("SECURITY ALERT", f"Brute-force attack suspected!\n{fails} failed logins for '{user}' "
                                                         "within 5 minutes.")
            self.l_result.config(text="ALERT: brute-force suspected", fg=RED)

    def simulate_attack(self):
        for _ in range(10):
            run("INSERT INTO login_log (username, success) VALUES (%s,0)", (DEMO_USER,))
        self.check_bruteforce(DEMO_USER)
        self.refresh_login()

    def clear_login_log(self):
        if messagebox.askyesno("Confirm", "Delete the login attempts log?"):
            run("DELETE FROM login_log")
            self.l_result.config(text="")
            self.refresh_login()

    def refresh_login(self):
        rows = run("SELECT ts, username, success FROM login_log ORDER BY id DESC LIMIT 100", fetch=True)
        self.l_tree.delete(*self.l_tree.get_children())
        for ts, user, ok in rows:
            self.l_tree.insert("", "end", values=(ts, user, "Success" if ok else "Failed"), tags=("OK" if ok else "FAIL",))

    # ======================= Alerts tab =======================
    def build_alerts(self):
        top = ttk.Frame(self.t_alerts)
        top.pack(fill="x", padx=14, pady=10)
        ttk.Label(top, text="All security alerts (saved in MySQL)", font=("Arial", 12, "bold")).pack(side="left")
        ttk.Button(top, text="Clear Alerts", command=self.clear_alerts).pack(side="right")
        self.a_tree = self.make_alert_tree(self.t_alerts, height=22)

    def clear_alerts(self):
        if messagebox.askyesno("Confirm", "Delete all alerts?"):
            run("DELETE FROM alerts")
            self.refresh_all()

    # ======================= Refresh =======================
    def refresh_all(self):
        self.refresh_dashboard()
        self.refresh_urls()
        self.refresh_login()
        self.fill_alert_tree(self.a_tree, 200)


# ------------------------------- Master password + intro screens -------------------------------
def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


class BgScreen(tk.Canvas):
    """Full-window canvas with a background image; buttons/entries are placed on top."""

    def __init__(self, app, image_name):
        super().__init__(app, width=WIN_W, height=WIN_H, highlightthickness=0, bg=NAVY)
        self.app = app
        self.photo = None
        try:
            self.photo = ImageTk.PhotoImage(Image.open(os.path.join(SCREENS_DIR, image_name)))
            self.create_image(0, 0, image=self.photo, anchor="nw")
        except (OSError, FileNotFoundError):
            self.create_text(WIN_W // 2, 140, text="CyberShield", fill=WHITE, font=("Arial", 44, "bold"))
            self.create_text(WIN_W // 2, 200, text=f"(background image missing: screens/{image_name})",
                             fill="#94A3B8", font=("Arial", 12))

    def button(self, text, y, command, width=16):
        b = tk.Button(self, text=text, command=command, width=width, font=("Arial", 13, "bold"),
                      bg=ACCENT, fg=NAVY, activebackground="#6EE7B7", activeforeground=NAVY,
                      relief="flat", cursor="hand2", pady=6)
        self.create_window(WIN_W // 2, y, window=b)
        return b

    def entry(self, y, var):
        e = tk.Entry(self, textvariable=var, show="*", width=26, font=("Arial", 14), justify="center",
                     bg=FIELD, fg=WHITE, insertbackground=WHITE, relief="flat",
                     highlightthickness=2, highlightbackground="#334155", highlightcolor=ACCENT)
        self.create_window(WIN_W // 2, y, window=e, height=38)
        return e


class PasswordScreen(BgScreen):
    """Step 1: master password. First run creates it. 3 wrong attempts close the program."""

    def __init__(self, app):
        super().__init__(app, "1_password_bg.png")
        meta = run("SELECT salt, pw_hash FROM app_meta WHERE id=1", fetch=True)
        self.meta = meta[0] if meta else None
        self.attempts = 0
        self.pw, self.pw2 = tk.StringVar(), tk.StringVar()
        self.status = None
        if self.meta:
            self.e1 = self.entry(480, self.pw)
            self.button("Submit", 548, self.submit)
            self.status = self.create_text(WIN_W // 2, 600, text="", fill="#F87171", font=("Arial", 12, "bold"))
        else:
            self.create_text(WIN_W // 2, 466, fill=ACCENT, font=("Arial", 11),
                             text="First run: create your master password (min 8 characters) and confirm it")
            self.e1 = self.entry(498, self.pw)
            e2 = self.entry(540, self.pw2)
            e2.bind("<Return>", lambda ev: self.submit())
            self.button("Create & Submit", 590, self.submit)
        self.e1.bind("<Return>", lambda ev: self.submit())
        self.e1.focus_set()

    def submit(self):
        pw = self.pw.get()
        if self.meta is None:
            if len(pw) < 8:
                return messagebox.showerror("Weak password", "Master password must be at least 8 characters.")
            if pw != self.pw2.get():
                return messagebox.showerror("Mismatch", "Both passwords must match.")
            salt = os.urandom(16)
            run("INSERT INTO app_meta (id, salt, pw_hash) VALUES (1, %s, %s)", (salt, hash_password(pw, salt)))
            self.app.login_ok()
            return
        if hmac.compare_digest(hash_password(pw, bytes(self.meta[0])), self.meta[1]):
            self.app.login_ok()
            return
        self.attempts += 1
        self.pw.set("")
        left = MAX_ATTEMPTS - self.attempts
        if left <= 0:
            messagebox.showerror("Access denied", f"Incorrect password {MAX_ATTEMPTS} times.\nThe program will now exit.")
            self.app.destroy()
        else:
            self.itemconfig(self.status, text=f"Attempts left: {left}")
            messagebox.showerror("Incorrect password", f"Incorrect password. Try again.\nAttempts left: {left}")


class WelcomeScreen(BgScreen):
    """Step 2: welcome screen with the Welcome button."""

    def __init__(self, app):
        super().__init__(app, "2_welcome_bg.png")
        self.button("Welcome", 545, app.show_info)


class InfoScreen(BgScreen):
    """Step 3: purpose, uses, benefits, conditions + I Agree button."""

    def __init__(self, app):
        super().__init__(app, "3_info_bg.png")
        self.button("I Agree", 600, app.show_loading)


class LoadingScreen(BgScreen):
    """Step 4: animated loading bar (about 3.5 seconds)."""

    def __init__(self, app):
        super().__init__(app, "4_loading_bg.png")
        style = ttk.Style()
        style.configure("Shield.Horizontal.TProgressbar", troughcolor=FIELD, background=ACCENT,
                        bordercolor="#334155", lightcolor=ACCENT, darkcolor=ACCENT)
        self.bar = ttk.Progressbar(self, style="Shield.Horizontal.TProgressbar", length=520,
                                   maximum=100, mode="determinate")
        self.create_window(WIN_W // 2, 500, window=self.bar, height=20)
        self.pct = self.create_text(WIN_W // 2, 540, text="0%", fill=ACCENT, font=("Arial", 14, "bold"))
        self.value = 0
        self.step()

    def step(self):
        self.value += 1
        self.bar["value"] = self.value
        self.itemconfig(self.pct, text=f"{self.value}%")
        if self.value >= 100:
            self.after(300, self.app.show_final)
        else:
            self.after(35, self.step)


class FinalScreen(BgScreen):
    """Step 5: WELCOME TO CyberShield + Start button -> dashboard."""

    def __init__(self, app):
        super().__init__(app, "5_final_bg.png")
        self.button("Start", 580, app.show_dashboard)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberShield - Personal Cyber Security Suite")
        ttk.Style(self).theme_use("clam")
        self.current = None
        self.set_size(WIN_W, WIN_H)
        self.swap(PasswordScreen(self))

    def set_size(self, w, h, resizable=False):
        self.update_idletasks()
        x = (self.winfo_screenwidth() - w) // 2
        y = max((self.winfo_screenheight() - h) // 2 - 20, 0)
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.resizable(resizable, resizable)

    def swap(self, frame):
        if self.current:
            self.current.destroy()
        self.current = frame
        frame.pack(fill="both", expand=True)

    def login_ok(self):
        self.swap(WelcomeScreen(self))

    def show_info(self):
        self.swap(InfoScreen(self))

    def show_loading(self):
        self.swap(LoadingScreen(self))

    def show_final(self):
        self.swap(FinalScreen(self))

    def show_dashboard(self):
        self.set_size(1020, 700, resizable=True)
        self.swap(Dashboard(self))


if __name__ == "__main__":
    try:
        init_db()
    except mysql.connector.Error as e:
        print("MySQL connection failed. Check DB_CONFIG (user/password) and that MySQL/XAMPP is running.\n", e)
        raise SystemExit(1)
    App().mainloop()
