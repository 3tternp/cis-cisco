
import re
import os
import datetime
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "CIS Cisco IOS 17.x Config Auditor (GUI)"
VERSION = "1.0"

# ----------------------------
# Helper: simple config parser
# ----------------------------

class IOSConfig:
    def __init__(self, text):
        self.raw = text
        # Normalize whitespace and keep line structure
        self.lines = [ln.rstrip() for ln in text.splitlines()]
        self.text = "\n".join(self.lines)
        # Build section maps for line stanzas (console, vty, aux, http, etc.)
        self.sections = self._parse_sections()

    def _parse_sections(self):
        sections = {}
        current_key = None
        current_body = []
        for ln in self.lines:
            m = re.match(r"^(\S.*)$", ln)
            if not m:
                continue
            line = m.group(1)
            # Identify section headers commonly used in IOS configs
            if re.match(r"^line\s+con\s+0", line):
                if current_key:
                    sections[current_key] = current_body
                current_key = ("line con 0",)
                current_body = []
            elif re.match(r"^line\s+aux\s+0", line):
                if current_key:
                    sections[current_key] = current_body
                current_key = ("line aux 0",)
                current_body = []
            elif re.match(r"^line\s+vty\s+\d+(\s+\d+)?", line):
                if current_key:
                    sections[current_key] = current_body
                # Store the exact header line as key for vty range
                current_key = (line.strip(),)
                current_body = []
            elif re.match(r"^ip http", line) or re.match(r"^ip http secure-server", line):
                # part of global; keep as global, not section
                pass
            elif re.match(r"^\S", line) and not line.startswith(" "):
                # New global stanza (like interface ...). Close any open line section.
                if current_key:
                    sections[current_key] = current_body
                    current_key = None
                    current_body = []
            else:
                # Body of section
                if current_key:
                    current_body.append(line.strip())
        if current_key:
            sections[current_key] = current_body
        return sections

    def has_line(self, pattern):
        return re.search(pattern, self.text, re.MULTILINE) is not None

    def findall(self, pattern):
        return re.findall(pattern, self.text, re.MULTILINE)

    def get_section_body(self, key_prefix):
        # key_prefix: e.g., "line vty", "line con 0"
        for key in self.sections:
            if key[0].startswith(key_prefix):
                return self.sections[key]
        return []

    def get_all_vty_sections(self):
        return {k: v for k, v in self.sections.items() if k[0].startswith("line vty")}


# ----------------------------
# Bench Check Definition
# ----------------------------

class CheckResult:
    def __init__(self, finding_id, issue_name, risk, status, manual, fix_type, remediation, rationale=None, details=None):
        self.finding_id = finding_id
        self.issue_name = issue_name
        self.risk = risk
        self.status = status  # Pass/Fail/Not_Applicable
        self.manual = manual  # Manual verification required? True/False
        self.fix_type = fix_type  # quick / planned / involved
        self.remediation = remediation
        self.rationale = rationale or ""
        self.details = details or ""

    def as_row(self):
        return {
            "Finding ID": self.finding_id,
            "Issue Name": self.issue_name,
            "Risk": self.risk,
            "Status": self.status,
            "Manual": "Yes" if self.manual else "No",
            "Fix Type": self.fix_type,
            "Remediation": self.remediation,
            "Details": self.details
        }


# ----------------------------
# CIS-mapped checks (subset)
# ----------------------------

def evaluate_checks(cfg: IOSConfig):
    results = []

    # Utility: exec-timeout check in a given section body list
    def check_exec_timeout(section_body):
        # exec-timeout <minutes> <seconds>
        for ln in section_body:
            m = re.match(r"^exec-timeout\s+(\d+)\s+(\d+)", ln)
            if m:
                minutes = int(m.group(1))
                # seconds = int(m.group(2))
                return minutes <= 10
        return False

    # 1.1.1 Enable 'aaa new-model'
    present = cfg.has_line(r"^aaa\s+new-model")
    results.append(CheckResult(
        "1.1.1",
        "Enable 'aaa new-model'",
        "High",
        "Pass" if present else "Fail",
        False,
        "involved",
        "Configure AAA globally: 'aaa new-model'",
        details="Found 'aaa new-model' in configuration" if present else "Missing 'aaa new-model'"
    ))

    # 1.1.2 Enable 'aaa authentication login' (basic presence)
    present = cfg.has_line(r"^aaa\s+authentication\s+login\s+")
    results.append(CheckResult(
        "1.1.2",
        "Enable 'aaa authentication login'",
        "High",
        "Pass" if present else "Fail",
        False,
        "involved",
        "Configure AAA login authentication (with fallback to local): e.g., \"aaa authentication login default group radius local\" or TACACS+ as applicable."
    ))

    # 1.2.2 Set 'transport input ssh' for 'line vty'
    only_ssh = True
    vty_sections = cfg.get_all_vty_sections()
    if not vty_sections:
        only_ssh = False
    else:
        for _, body in vty_sections.items():
            trans_lines = [ln for ln in body if ln.startswith("transport input")]
            if not trans_lines:
                only_ssh = False
                break
            for tl in trans_lines:
                # allow "ssh" or "ssh telnet"? CIS requires only ssh.
                m = re.match(r"transport input\s+(.+)$", tl)
                if m:
                    methods = m.group(1).strip().split()
                    if methods != ["ssh"]:
                        only_ssh = False
                        break
    results.append(CheckResult(
        "1.2.2",
        "Set 'transport input ssh' for 'line vty' connections",
        "High",
        "Pass" if only_ssh else "Fail",
        False,
        "quick",
        "Under all VTY lines: 'transport input ssh' (remove telnet/others)."
    ))

    # 2.1.1.2 Set 'ip ssh version 2'
    sshv2 = cfg.has_line(r"^ip\s+ssh\s+version\s+2")
    results.append(CheckResult(
        "2.1.1.2",
        "Set 'ip ssh version 2'",
        "High",
        "Pass" if sshv2 else "Fail",
        False,
        "quick",
        "Globally set SSH v2: 'ip ssh version 2'."
    ))

    # 1.5.2 Unset 'private' for 'snmp-server community'
    has_private = cfg.has_line(r"^snmp-server\s+community\s+private(\s|$)")
    results.append(CheckResult(
        "1.5.2",
        "Unset 'private' SNMP community",
        "Critical",
        "Fail" if has_private else "Pass",
        False,
        "quick",
        "Remove default community: 'no snmp-server community private'. Prefer SNMPv3.",
        details="Found 'snmp-server community private'." if has_private else "No default 'private' community found."
    ))

    # 1.5.3 Unset 'public' for 'snmp-server community'
    has_public = cfg.has_line(r"^snmp-server\s+community\s+public(\s|$)")
    results.append(CheckResult(
        "1.5.3",
        "Unset 'public' SNMP community",
        "Critical",
        "Fail" if has_public else "Pass",
        False,
        "quick",
        "Remove default community: 'no snmp-server community public'. Prefer SNMPv3.",
        details="Found 'snmp-server community public'." if has_public else "No default 'public' community found."
    ))

    # 1.4.1 Set 'password' for 'enable secret' (check presence)
    enable_secret = cfg.has_line(r"^enable\s+secret\s+")
    results.append(CheckResult(
        "1.4.1",
        "Set 'enable secret' password",
        "High",
        "Pass" if enable_secret else "Fail",
        False,
        "quick",
        "Configure: 'enable secret <STRONG_PASSWORD>'."
    ))

    # 1.4.2 service password-encryption
    svc_pwd_enc = cfg.has_line(r"^service\s+password-encryption")
    results.append(CheckResult(
        "1.4.2",
        "Enable 'service password-encryption'",
        "Medium",
        "Pass" if svc_pwd_enc else "Fail",
        False,
        "quick",
        "Configure: 'service password-encryption'."
    ))

    # 1.4.3 username secret for all local users (basic check: at least one "username ... secret ...")
    any_user_secret = cfg.has_line(r"^username\s+\S+\s+secret\s+")
    results.append(CheckResult(
        "1.4.3",
        "Use 'username <name> secret <hash>' for local users",
        "High",
        "Pass" if any_user_secret else "Fail",
        True,  # manual to ensure ALL users use secret
        "planned",
        "Create/convert local users to use 'username <name> secret <hash>' and remove 'username ... password ...' entries."
    ))

    # 1.2.6/1.2.7/1.2.8/1.2.9 exec-timeout <= 10 on aux/console/tty/vty
    aux_ok = check_exec_timeout(cfg.get_section_body("line aux 0"))
    results.append(CheckResult(
        "1.2.6",
        "Set 'exec-timeout' <= 10 on 'line aux 0'",
        "Medium",
        "Pass" if aux_ok else "Fail",
        False,
        "quick",
        "Under 'line aux 0': 'exec-timeout 10 0' (or less)."
    ))

    con_ok = check_exec_timeout(cfg.get_section_body("line con 0"))
    results.append(CheckResult(
        "1.2.7",
        "Set 'exec-timeout' <= 10 on 'line console 0'",
        "Medium",
        "Pass" if con_ok else "Fail",
        False,
        "quick",
        "Under 'line con 0': 'exec-timeout 10 0' (or less)."
    ))

    # tty sections may not be explicit; mark as manual if not found
    tty_section = cfg.get_section_body("line tty")
    tty_ok = check_exec_timeout(tty_section) if tty_section else False
    results.append(CheckResult(
        "1.2.8",
        "Set 'exec-timeout' <= 10 on 'line tty'",
        "Medium",
        "Pass" if tty_ok else "Fail",
        True if not tty_section else False,
        "quick",
        "Under 'line tty <n>': 'exec-timeout 10 0' (or less)."
    ))

    vty_ok_all = True
    if vty_sections:
        for _, body in vty_sections.items():
            if not check_exec_timeout(body):
                vty_ok_all = False
                break
    else:
        vty_ok_all = False
    results.append(CheckResult(
        "1.2.9",
        "Set 'exec-timeout' <= 10 on 'line vty'",
        "Medium",
        "Pass" if vty_ok_all else "Fail",
        False if vty_sections else True,
        "quick",
        "Under each 'line vty' range: 'exec-timeout 10 0' (or less)."
    ))

    # 1.2.5 access-class on vty (presence)
    vty_acl_ok = False
    if vty_sections:
        vty_acl_ok = all(any(ln.startswith("access-class ") for ln in body) for body in vty_sections.values())
    results.append(CheckResult(
        "1.2.5",
        "Apply 'access-class' on all 'line vty'",
        "High",
        "Pass" if vty_acl_ok else "Fail",
        False if vty_sections else True,
        "planned",
        "Define mgmt ACL (e.g., 'ip access-list standard VTY-MGMT' then 'permit <trusted-subnets>') and apply under all VTY lines: 'access-class VTY-MGMT in'."
    ))

    # 2.1.2 'no cdp run' (CDP disabled globally)
    cdp_disabled = cfg.has_line(r"^no\s+cdp\s+run")
    results.append(CheckResult(
        "2.1.2",
        "Disable CDP globally ('no cdp run')",
        "Medium",
        "Pass" if cdp_disabled else "Fail",
        True,  # manual context: may be required in some designs
        "planned",
        "If not required, disable Cisco Discovery Protocol: 'no cdp run'. If required, restrict at interfaces."
    ))

    # 2.1.3 'no ip bootp server'
    no_bootp = cfg.has_line(r"^no\s+ip\s+bootp\s+server")
    results.append(CheckResult(
        "2.1.3",
        "Disable BOOTP server ('no ip bootp server')",
        "Low",
        "Pass" if no_bootp else "Fail",
        False,
        "quick",
        "Disable BOOTP: 'no ip bootp server'."
    ))

    # 2.1.4 'no service dhcp'
    no_dhcp = cfg.has_line(r"^no\s+service\s+dhcp")
    results.append(CheckResult(
        "2.1.4",
        "Disable DHCP service ('no service dhcp')",
        "Low",
        "Pass" if no_dhcp else "Fail",
        False,
        "quick",
        "Disable DHCP if not used: 'no service dhcp'."
    ))

    # 1.5.1 Disable SNMP when unused: simple heuristic—no snmp-server lines at all OR explicit 'no snmp-server'
    snmp_any = bool(re.findall(r"^snmp-server\s+", cfg.text, re.MULTILINE))
    disable_snmp_line = cfg.has_line(r"^no\s+snmp-server")
    snmp_disabled = disable_snmp_line or (not snmp_any)
    results.append(CheckResult(
        "1.5.1",
        "Disable SNMP when unused",
        "Medium",
        "Pass" if snmp_disabled else "Fail",
        True,  # manual: confirm it's unused in environment
        "planned",
        "If unused, remove SNMP: 'no snmp-server'. If used, prefer SNMPv3 with authPriv."
    ))

    # 2.2.x logging summary presence checks
    logging_enable = cfg.has_line(r"^logging\s+on$|^logging enable$|^logging\s+host\s+")
    results.append(CheckResult(
        "2.2.x",
        "Enable and configure logging (buffered/console/host/trap/timestamps)",
        "Medium",
        "Pass" if logging_enable else "Fail",
        True,
        "planned",
        "Configure 'logging buffered <size>', 'logging host <ip>', 'logging trap informational', 'service timestamps debug datetime', 'login on-failure log', etc."
    ))

    # 2.1.1.1.3 RSA modulus >= 2048 (basic parse)
    rsa_mod_match = re.search(r"^crypto\s+key\s+generate\s+rsa\s+.*modulus\s+(\d+)", cfg.text, re.MULTILINE)
    rsa_ok = False
    if rsa_mod_match:
        try:
            rsa_ok = int(rsa_mod_match.group(1)) >= 2048
        except:
            rsa_ok = False
    results.append(CheckResult(
        "2.1.1.1.3",
        "SSH RSA key length >= 2048",
        "High",
        "Pass" if rsa_ok else "Fail",
        False,
        "quick",
        "Regenerate keys with >= 2048 bits: 'crypto key generate rsa modulus 2048' (after setting hostname and ip domain-name)."
    ))

    return results


# ----------------------------
# HTML report builder
# ----------------------------

def build_html(report_title, device_name, results):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = ""
    pass_count = sum(1 for r in results if r.status == "Pass")
    fail_count = sum(1 for r in results if r.status == "Fail")
    na_count = sum(1 for r in results if r.status == "Not_Applicable")
    total = len(results)

    for r in results:
        status_color = "#2e7d32" if r.status == "Pass" else ("#c62828" if r.status == "Fail" else "#6a1b9a")
        risk_badge = {
            "Critical": "#b71c1c",
            "High": "#e65100",
            "Medium": "#f9a825",
            "Low": "#2e7d32"
        }.get(r.risk, "#546e7a")
        manual_badge = "#1565c0" if r.manual else "#455a64"
        fix_badge = {
            "quick": "#2e7d32",
            "planned": "#0277bd",
            "involved": "#6a1b9a"
        }.get(r.fix_type, "#546e7a")

        rows += f"""
        <tr>
            <td>{r.finding_id}</td>
            <td>{r.issue_name}</td>
            <td><span class="badge" style="background:{risk_badge}">{r.risk}</span></td>
            <td><span class="badge" style="background:{status_color}">{r.status}</span></td>
            <td><span class="badge" style="background:{manual_badge}">{'Manual' if r.manual else 'Auto'}</span></td>
            <td><span class="badge" style="background:{fix_badge}">{r.fix_type}</span></td>
            <td><code>{r.remediation}</code></td>
            <td>{r.details}</td>
        </tr>
        """

    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{report_title}</title>
<style>
body {{ font-family: -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif; margin: 24px; }}
h1 {{ margin-bottom: 0; }}
.sub {{ color:#555; margin-top:4px; }}
table {{ width:100%; border-collapse: collapse; margin-top:20px; }}
th, td {{ border:1px solid #e0e0e0; padding:8px 10px; text-align:left; vertical-align:top; }}
th {{ background:#f5f5f5; position:sticky; top:0; z-index:1; }}
.badge {{ color:#fff; padding:3px 8px; border-radius:999px; font-size:12px; }}
.summary {{ margin-top: 10px; }}
.codebox {{ background:#f7f7f9; border:1px solid #e1e1e8; border-radius:8px; padding:12px; overflow:auto; }}
.footer {{ margin-top:30px; color:#777; font-size:12px; }}
</style>
</head>
<body>
<h1>{report_title}</h1>
<div class="sub">Device: <b>{device_name or 'N/A'}</b> • Generated: {now} • App: {APP_TITLE} v{VERSION}</div>
<div class="summary">
<b>Summary:</b> {pass_count} Pass • {fail_count} Fail • {na_count} N/A • Total {total}
</div>
<table>
<thead>
<tr>
<th>Finding ID</th>
<th>Issue Name</th>
<th>Risk</th>
<th>Status</th>
<th>Assessment</th>
<th>Fix Type</th>
<th>Remediation</th>
<th>Details</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>

<div class="footer">
<p><b>Standard:</b> CIS Cisco IOS 17.x Benchmark v1.0.0 (selected automated controls).
This report is an assistive tool and may require manual verification for certain findings.</p>
</div>
</body>
</html>
"""
    return html


# ----------------------------
# GUI app
# ----------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("720x420")
        self.resizable(True, True)

        self.config_path = tk.StringVar()
        self.device_name = tk.StringVar()

        # UI
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Device Name (optional):").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.device_name, width=40).grid(row=0, column=1, sticky="we", padx=8)

        ttk.Label(frm, text="Cisco IOS running-config file:").grid(row=1, column=0, sticky="w", pady=(10,0))
        ent = ttk.Entry(frm, textvariable=self.config_path, width=60)
        ent.grid(row=1, column=1, sticky="we", padx=8, pady=(10,0))
        ttk.Button(frm, text="Browse…", command=self.browse_config).grid(row=1, column=2, sticky="w", pady=(10,0))

        self.run_btn = ttk.Button(frm, text="Generate HTML Report", command=self.run_audit)
        self.run_btn.grid(row=3, column=1, pady=20)

        self.status_lbl = ttk.Label(frm, text="", foreground="#555")
        self.status_lbl.grid(row=4, column=1, sticky="w")

        for i in range(3):
            frm.columnconfigure(i, weight=1)

    def browse_config(self):
        path = filedialog.askopenfilename(
            title="Select Cisco IOS running-config (text)",
            filetypes=[("Text files", "*.txt *.cfg *.conf *.config *.ios"), ("All files", "*.*")]
        )
        if path:
            self.config_path.set(path)

    def run_audit(self):
        path = self.config_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror(APP_TITLE, "Please select a valid configuration file.")
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Failed to read file:\n{e}")
            return

        cfg = IOSConfig(text)
        results = evaluate_checks(cfg)

        report_title = "CIS Cisco IOS 17.x Audit Report"
        html = build_html(report_title, self.device_name.get().strip(), results)

        out_name = f"cis_ios_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        out_path = os.path.join(os.path.expanduser("~"), "Desktop", out_name)
        # Fallback to same folder if Desktop not writable
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html)
        except Exception:
            out_path = os.path.join(os.path.dirname(path), out_name)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html)

        self.status_lbl.config(text=f"Report saved to: {out_path}")
        try:
            webbrowser.open(f"file://{out_path}")
        except Exception:
            pass

if __name__ == "__main__":
    app = App()
    app.mainloop()
