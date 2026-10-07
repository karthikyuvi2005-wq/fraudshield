import pandas as pd
import os
import nbformat as nbf

# 1. Load the dataset using latin-1 encoding
df = pd.read_csv("spam.csv", encoding="latin-1")

# 2. Select only relevant columns
df = df[["v1", "v2"]]

# 3. Rename columns
df.columns = ["label", "text"]

# 4. Map binary labels (0 = Safe, 1 = Fraud/Spam)
df["label"] = df["label"].map({"ham": 0, "spam": 1})

# 5. Remove duplicates and reset index
df = df.drop_duplicates().reset_index(drop=True)

# 5b. Enrich with modern cyber threat, banking hack, KYC, and digital arrest samples
modern_samples = [
    # Modern Fraud: Banking Hack, Breach & Security Panics (label=1)
    {"text": "Alert: Your bank account is hacked! Click immediately to secure your funds before they are transferred.", "label": 1},
    {"text": "Warning: bank is hacked. Verify your identity now to prevent permanent account suspension.", "label": 1},
    {"text": "bank is hacked", "label": 1},
    {"text": "Your bank account has been hacked by malicious attackers. Call helpline immediately.", "label": 1},
    {"text": "Security breach: Your bank account has been compromised. Log in here to reset your credentials.", "label": 1},
    {"text": "SBI Alert: Bank server is hacked. Transfer your balance to RBI safe vault account immediately.", "label": 1},
    {"text": "Dear customer, unauthorized login attempt detected from Russia. Your bank is hacked. Reset password now.", "label": 1},
    {"text": "Your bank account has been hacked by cyber attackers. Immediate verification required.", "label": 1},
    {"text": "Urgent: Multiple unauthorized transactions detected. Bank account compromised. Act now.", "label": 1},
    {"text": "Critical security warning: System detected that your bank account is hacked. Click to lock account.", "label": 1},
    {"text": "Account hacked alert: Unauthorized device accessed your netbanking. Click to freeze funds.", "label": 1},
    {"text": "Bank alert: Security breach detected on your savings account. Update password immediately.", "label": 1},
    {"text": "Hacked warning: Your banking credentials have been compromised on the dark web.", "label": 1},
    {"text": "Notice: Your bank is compromised. Verify your debit card number and CVV to restore access.", "label": 1},
    {"text": "Urgent notification: Bank database breach. Confirm your PAN and PIN to protect your savings.", "label": 1},
    {"text": "Malware detected on your phone accessing bank portal. Install security patch immediately.", "label": 1},
    {"text": "Ransomware warning: Bank database encrypted. Pay ransom or all account records will be deleted.", "label": 1},
    
    # Modern Fraud: KYC / Account Blocked Traps (label=1)
    {"text": "Dear SBI customer, your bank account is blocked due to pending KYC. Click http://sbi-kyc.xyz to update PAN.", "label": 1},
    {"text": "HDFC Alert: Your netbanking will be suspended tonight. Update Aadhaar and PAN card immediately.", "label": 1},
    {"text": "Your bank account has been frozen by RBI due to non-compliance. Call officer immediately.", "label": 1},
    {"text": "ICICI Bank: Your debit card is deactivated. Verify KYC details within 24 hours to avoid closure.", "label": 1},
    {"text": "Axis Bank warning: Incomplete KYC document. Your account is restricted. Update now.", "label": 1},
    {"text": "PNB Alert: Account locked. Submit PAN card and date of birth to unfreeze your account.", "label": 1},
    {"text": "Your Paytm wallet is blocked. Complete video KYC verification immediately to restore access.", "label": 1},
    {"text": "SIM card deactivation alert: Your mobile number will be blocked in 2 hours. Update KYC.", "label": 1},

    # Modern Fraud: Digital Arrest & Law Enforcement Extortion (label=1)
    {"text": "CBI Cyber Cell: Digital arrest warrant issued against you for money laundering. Join Skype interrogation.", "label": 1},
    {"text": "Police notice: Illegal narcotics and passports seized in your FedEx courier. Contact officer immediately to avoid arrest.", "label": 1},
    {"text": "Supreme Court notice: Non-bailable arrest warrant registered on your Aadhaar. Pay penalty to settle case.", "label": 1},
    {"text": "Customs Department: Contraband drugs detected in your international parcel. Digital arrest initiated.", "label": 1},
    {"text": "ED summons: Your bank accounts have been seized under PMLA act. Contact investigating officer now.", "label": 1},

    # Modern Fraud: Utility & Electricity Bill Traps (label=1)
    {"text": "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Call 9876543210.", "label": 1},
    {"text": "Electricity Board: Power cut scheduled for your meter due to bill discrepancy. Contact executive immediately.", "label": 1},
    {"text": "Urgent: Gas pipeline supply will be terminated today. Call customer care officer to clear arrears.", "label": 1},

    # Modern Fraud: UPI QR & Lottery / Work-From-Home (label=1)
    {"text": "Congratulations! You won Rs. 25,00,000 in KBC lottery. Pay Rs. 500 registration charge via UPI to claim prize.", "label": 1},
    {"text": "Work from home task: Earn Rs. 5,00,000 daily by liking YouTube videos and subscribing to Telegram channels.", "label": 1},
    {"text": "Pre-approved instant personal loan of Rs. 5,00,000 with zero interest and no CIBIL check. Apply now.", "label": 1},
    {"text": "Income tax refund of Rs. 18,450 approved. Provide bank account details and OTP to receive credit.", "label": 1},

    # Modern Safe / Legitimate Technical Messages (label=0)
    {"text": "The bank is closed on Sundays and national holidays for routine branch maintenance.", "label": 0},
    {"text": "I visited the bank branch today to deposit a check and request a new chequebook.", "label": 0},
    {"text": "We learned about ethical hacking and penetration testing in our computer science lecture.", "label": 0},
    {"text": "The university symposium on cybersecurity will host lectures on firewall defense and encryption.", "label": 0},
    {"text": "Please remember to study the chapter on data structures and algorithms for tomorrow's exam.", "label": 0},
    {"text": "Hey, are you free this evening for a quick cup of coffee after college classes?", "label": 0},
    {"text": "The bank sent an email confirming that my monthly e-statement is available for download.", "label": 0},
    {"text": "Our team completed the software engineering project ahead of the hackathon deadline.", "label": 0},
    {"text": "He works as a cybersecurity researcher analyzing malware signatures and software patches.", "label": 0},
    {"text": "Don't forget to submit your lab assignment on computer networks before 5 PM today.", "label": 0}
]

df_modern = pd.DataFrame(modern_samples)
df = pd.concat([df, df_modern], ignore_index=True)
df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)

# 6. Save clean dataset for pipeline use
os.makedirs("data", exist_ok=True)
df.to_csv("data/clean_sms.csv", index=False)

print("=" * 45)
print("[SUCCESS] STEP 2 COMPLETE: DATA LOADED & CLEANED")
print("=" * 45)
print(f"Total clean samples : {len(df)}")
safe_count = (df["label"] == 0).sum()
fraud_count = (df["label"] == 1).sum()
print(f"Safe messages (0)   : {safe_count} ({safe_count/len(df)*100:.1f}%)")
print(f"Fraud messages (1)  : {fraud_count} ({fraud_count/len(df)*100:.1f}%)")
print("-" * 45)
print("Sample cleaned messages:")
for idx, row in df.head(3).iterrows():
    tag = "SAFE " if row["label"] == 0 else "FRAUD"
    print(f"[{tag}] {row['text'][:65]}...")
print("=" * 45)

# 7. Initialize / write fraudshield_notebook.ipynb
nb = nbf.v4.new_notebook()

md_header = """# FraudShield AI: End-to-End Pipeline
**Team**: Hackscribe  
**Theme**: Future of Fraud Detection and Prevention  

---
## Step 2: Load and Clean SMS Spam Collection Dataset
- **Source**: UCI Machine Learning Repository (SMS Spam Collection by Tiago A. Almeida & José María Gómez Hidalgo)
- **Goal**: Clean text data, encode binary labels (`0 = Safe`, `1 = Fraud`), remove duplicate messages, and structure data for NLP."""

code_step2 = """import pandas as pd

# Load UCI SMS dataset with latin-1 encoding
df = pd.read_csv("spam.csv", encoding="latin-1")

# Keep only message and label columns
df = df[["v1", "v2"]]
df.columns = ["label", "text"]

# Encode targets: 0 = Safe (ham), 1 = Fraud (spam)
df["label"] = df["label"].map({"ham": 0, "spam": 1})

# Drop duplicates & reset index
df = df.drop_duplicates().reset_index(drop=True)

# Save cleaned dataset
df.to_csv("data/clean_sms.csv", index=False)

print(f"Total clean samples: {len(df)}")
print(df["label"].value_counts())
df.head()"""

nb.cells = [
    nbf.v4.new_markdown_cell(md_header),
    nbf.v4.new_code_cell(code_step2)
]

with open("fraudshield_notebook.ipynb", "w", encoding="utf-8") as f:
    nbf.write(nb, f)

print(" Notebook initialized at 'fraudshield_notebook.ipynb'")
