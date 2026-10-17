# CyberShield - Personal Cyber Security Suite
Python + MySQL + Tkinter

## Folder
    CyberShield_Project/
      cybershield.py   <- run this
      screens/         <- 5 background images (keep next to the .py file)
      logo.png         <- project logo (for report / PPT)
      requirements.txt
      README.md

## Run
1. Start MySQL (XAMPP Control Panel -> MySQL -> Start).
2. pip install -r requirements.txt
3. Open cybershield.py and check DB_CONFIG (XAMPP default: user "root", password "").
4. python cybershield.py   (database and tables are created automatically)

## Screen flow
1. Master password screen. First run: create the master password (min 8 characters) and confirm it.
   3 wrong attempts -> the program exits. The password is stored only as a salted PBKDF2 hash.
2. Welcome screen -> "Welcome" button
3. Info screen (purpose, uses, benefits, conditions) -> "I Agree" button
4. Loading screen
5. "WELCOME TO CyberShield" -> "Start" button
6. Dashboard

## Modules
1. Phishing URL Detector: risk score 0-100 (SAFE / SUSPICIOUS / DANGEROUS) with reasons. The link is never opened.
2. File Integrity Monitor: saves a SHA-256 baseline of files; Scan shows OK / TAMPERED / MISSING.
3. Login Attack Monitor: demo login portal (admin / Admin@123). 3+ failed logins in 5 minutes = brute-force alert.
4. Dashboard + Alerts: counters, bar chart, latest alerts. Everything is saved in MySQL (database: cybershield_db).

## 5-minute demo script
1. Problem (30s): phishing links, tampered files and brute-force logins are common; normal users have no simple tool.
2. Start the program: enter a wrong password once (shows attempts left), then the correct one. Go through the screens.
3. Phishing tab: pick the sample "https://www.google.com" -> SAFE.
   Pick "http://192.168.1.5/verify-login@bank.com" -> DANGEROUS, read out the reasons.
4. File Integrity tab: click "Create Demo File", open cybershield_demo.txt in Notepad, change the text, save.
   Click "Scan All Files" -> TAMPERED.
5. Login Monitor tab: enter wrong passwords 3 times (or click "Simulate Attack") -> security alert pop-up.
6. Dashboard tab: show counters and chart. Open phpMyAdmin -> cybershield_db -> alerts table.
7. Impact and future (30s): auto-monitoring, email scanning, machine learning, connect to real login systems.

## Honest limitations (say these to the judges)
- Rule-based: false positives and false negatives are possible. SAFE does not guarantee a site is trustworthy.
- File scan and URL check are manual, not real-time.
- Login monitor works on the demo portal, not on real systems.
- If the master password is forgotten it cannot be recovered (to reset: delete the app_meta table row in phpMyAdmin).
