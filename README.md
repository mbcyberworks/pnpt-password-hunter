# pnpt-password-hunter
This repository contains a small Bash helper script used during Linux privilege escalation to surface potential credentials and relevant context.   It is designed to support a **manual-first PNPT-style workflow** and does not perform exploitation or automated privilege escalation.

---

## Purpose

During privilege escalation, credentials are often exposed in predictable but easy-to-miss locations:

- shell history files  
- environment variables  
- configuration files  
- backups and logs  
- leftover SSH keys

This script helps **systematically surface those locations**, so the operator can focus on **analysis instead of guesswork**.

---

## What this script does

- Searches common locations for **potential plaintext credentials**  
- Inspects user and process context relevant to privilege escalation  
- Highlights findings without exploiting them  
- Supports different modes depending on time and environment

---

## What this script does **not** do

- ❌ No exploitation  
- ❌ No password cracking  
- ❌ No brute forcing  
- ❌ No automatic privilege escalation  
- ❌ No system modification

All findings require **manual review and verification**.

---

## Workflow position (important)

This script is intended to be used **after initial access** and **before or alongside manual enumeration**, for example:

```
Initial Shell
   ↓
Manual Enumeration (id, sudo -l, filesystem context)
   ↓
PNPT Password Hunter (lead discovery)
   ↓
Manual Validation & Privilege Escalation
```

It is a **supporting tool**, not a replacement for understanding the system.

---

## Quick reference

Common findings and how to interpret them:

- `mysql -u root -p password` in shell history → Potential direct database access
- `env_keep+=LD_PRELOAD` in sudo configuration → Possible library injection vector
- Readable `/etc/shadow` or backups → Direct password hash access
- SSH private keys without passphrases → Lateral movement or persistence potential

---

## Exam note (PNPT context)

This script is designed for **learning environments and authorized penetration tests**.

During practical exams such as PNPT:
- Use with caution  
- Understand every finding  
- Be able to explain *why* a credential matters  
- Do not rely on automation over reasoning

---

## Example output
The script highlights findings using **color-coded text markers**:

- `[!]` **Critical findings**: Plaintext passwords, credentials, shadow access
- `[>]` **Scanning progress**: Files and locations being checked
- `[*]` **Context information**: User, system, and environment data
- `[i]` **Informational**: SSH keys, configuration notes

All findings require **manual validation and interpretation**.

---

## Usage

```bash
# Basic usage
chmod +x pnpt_password_hunter.sh
./pnpt_password_hunter.sh

# Available options
./pnpt_password_hunter.sh --help
./pnpt_password_hunter.sh --quick    # Fast scan (common locations)
./pnpt_password_hunter.sh --deep     # Comprehensive scan


---

## Ethical use & disclaimer

This script is provided for **educational purposes and authorized security testing only**.

You are responsible for ensuring you have **explicit permission** before using this tool on any system.

---

## Related content

This script is used and explained in the following case study:

> *Sudo privilege escalation case study – from enumeration to root*  
> (MB Cyberworks)

---

## License

MIT License
