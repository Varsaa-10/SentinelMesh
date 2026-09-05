"""
One-off generator for the 28 distractor technique records + 15 distractor
CVE records Person 1's changelog lists by filename but whose contents
weren't shared. Built from public MITRE ATT&CK / NVD facts, since these
are all real, identifiable, well-documented IDs.

IMPORTANT CAVEATS (also stamped into every generated file via
"_reconstructed_note"):
  - tactic/technique_name/description/CVE facts are accurate public data.
  - detection_signatures (log_tail vs falco, exact rule/detector names)
    are PLACEHOLDER routing guesses, not Person 1's actual lab wiring --
    these are distractors, so exact detection wiring doesn't affect
    scoring, but don't treat them as real if reused elsewhere.
  - scenario_refs is [] and is_scenario_critical is False for all of
    these, since none of the 8 scenario-critical techniques are in this
    list (they're already real/placeholder files elsewhere).
  - Where ATT&CK lists multiple tactics for a technique, one primary
    tactic was picked; note is included when a real record might file it
    under a different one of the valid tactics.

Run once, writes into kb/kb_master_real/{techniques,cves}/.
"""
import json
import os

OUT_TECH = "/home/claude/rag_engine/kb/kb_master_real/techniques"
OUT_CVE = "/home/claude/rag_engine/kb/kb_master_real/cves"
os.makedirs(OUT_TECH, exist_ok=True)
os.makedirs(OUT_CVE, exist_ok=True)

RECON_NOTE_TECH = (
    "RECONSTRUCTED FROM PUBLIC MITRE ATT&CK DATA, not Person 1's original file. "
    "tactic/technique_name/description are accurate public ATT&CK facts. "
    "detection_signatures below is a plausible placeholder routing, not lab-verified. "
    "This is a distractor (is_scenario_critical=false), so exact wiring doesn't affect "
    "scoring, but replace with the real file if/when available."
)
RECON_NOTE_CVE = (
    "RECONSTRUCTED FROM PUBLIC NVD DATA, not Person 1's original file. "
    "cve_id/description/cvss_score/affected_component are accurate public facts. "
    "lab_planted=false (only CVE-2022-29217 is lab-planted per the changelog). "
    "Replace with the real file if/when available."
)

# id: (tactic, technique_name, description, detection_source, mitigation, sub_technique_of)
TECHNIQUES = {
    "T1041": None,  # already have real/placeholder version, skip
    "T1048": ("Exfiltration", "Exfiltration Over Alternative Protocol",
        "Adversaries may steal data by exfiltrating it over a different protocol than that used by the existing command and control channel, such as FTP, DNS, or SMTP, to blend in or evade detection focused on the primary C2 channel.",
        "falco", "Egress filtering per-protocol, DNS query monitoring for tunneling patterns, restrict outbound protocols to an explicit allowlist."),
    "T1053.003": ("Persistence", "Scheduled Task/Job: Cron",
        "Adversaries may abuse the cron utility on Linux systems to perform task scheduling for initial or recurring execution of malicious code, achieving persistence or privilege escalation.",
        "falco", "Monitor changes to crontab files and /etc/cron.*, restrict write access to scheduling directories, alert on unexpected cron entries."),
    "T1059": ("Execution", "Command and Scripting Interpreter",
        "Adversaries may abuse command and script interpreters (e.g. bash, Python) to execute commands, scripts, or binaries, often spawned from a compromised web-facing process to achieve remote code execution.",
        "falco", "Application sandboxing, least-privilege containers, seccomp/AppArmor profiles restricting interpreter spawning from web-facing processes."),
    "T1068": ("Privilege Escalation", "Exploitation for Privilege Escalation",
        "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges, taking advantage of a programming error to run adversary-controlled code with higher permissions than intended.",
        "falco", "Timely patching of privilege escalation CVEs, minimize setuid binaries, kernel hardening, runtime privilege monitoring."),
    "T1070": None,  # already have
    "T1078": None,  # already have
    "T1080": ("Lateral Movement", "Taint Shared Content",
        "Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories, that will then be executed by other users.",
        "log_tail", "Restrict write access on shared storage, integrity monitoring on shared content, scan shared locations for known-bad artifacts."),
    "T1082": ("Discovery", "System Information Discovery",
        "Adversaries may attempt to get detailed information about the operating system and hardware of a compromised system, such as via uname, systeminfo, or reading container metadata endpoints.",
        "falco", "Restrict metadata endpoint access, command execution auditing, alert on bursts of system reconnaissance commands."),
    "T1083": ("Discovery", "File and Directory Discovery",
        "Adversaries may enumerate files and directories to gain an understanding of standard functionality and locate valuable information, often as a precursor to collection or lateral movement.",
        "falco", "File access auditing, restrict directory listing permissions on sensitive paths, monitor for high-volume filesystem enumeration."),
    "T1087": ("Discovery", "Account Discovery",
        "Adversaries may attempt to get a listing of valid accounts, group memberships, or configured permissions on a system to plan follow-on credential access or lateral movement.",
        "log_tail", "Restrict enumeration APIs and commands, monitor for anomalous account/group listing activity, apply least-privilege to discovery-capable tooling."),
    "T1098": ("Persistence", "Account Manipulation",
        "Adversaries may modify an existing account (e.g. adding permissions, credentials, or roles) to maintain access to a victim system after initial compromise.",
        "log_tail", "Change monitoring on IAM/account stores, periodic access review, alert on unexpected permission or credential changes to existing accounts."),
    "T1110": None,  # already have
    "T1133": ("Persistence", "External Remote Services",
        "Adversaries may leverage external-facing remote services (VPN, SSH, RDP) to gain initial access or maintain persistence within a network without needing malware.",
        "falco", "Restrict and monitor external-facing remote service access, require MFA, disable unused remote access services."),
    "T1136": ("Persistence", "Create Account",
        "Adversaries may create a new account, local or domain/cloud, to maintain access to a victim system using a credential they control rather than one that may be noticed and revoked.",
        "log_tail", "Monitor account creation events, restrict account-creation privileges, alert on accounts created outside normal provisioning workflows."),
    "T1190": None,  # already have
    "T1195": ("Initial Access", "Supply Chain Compromise",
        "Adversaries may manipulate products or product delivery mechanisms, including software dependencies, prior to receipt by a final consumer, to compromise downstream systems.",
        "log_tail", "Dependency pinning and integrity verification, software bill of materials (SBOM) tracking, vet third-party packages before adoption."),
    "T1212": None,  # already have
    "T1485": ("Impact", "Data Destruction",
        "Adversaries may destroy data and files on specific systems or in large numbers to interrupt availability, potentially rendering stored data irrecoverable via built-in file deletion or disk wiping.",
        "falco", "Immutable/versioned backups, restrict destructive file operation permissions, monitor for mass file deletion patterns."),
    "T1499": ("Impact", "Endpoint Denial of Service",
        "Adversaries may perform Endpoint Denial of Service attacks to degrade or block the availability of services to users, such as flooding a web application with requests to exhaust resources.",
        "falco", "Rate limiting, request throttling, autoscaling with alerting, upstream DDoS protection."),
    "T1528": ("Credential Access", "Steal Application Access Token",
        "Adversaries may steal application access tokens as a means of acquiring credentials to access remote systems and resources without needing to know the underlying username/password.",
        "log_tail", "Short-lived tokens with narrow scopes, token binding to client context, monitor for token use from unexpected sources."),
    "T1534": ("Lateral Movement", "Internal Spearphishing",
        "Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization after already having access to a valid account or system.",
        "log_tail", "Internal email/message content filtering, user awareness training, monitor for anomalous internal message patterns."),
    "T1539": ("Credential Access", "Steal Web Session Cookie",
        "Adversaries may steal web application or service session cookies to bypass authentication controls and access web applications or Internet services as an authenticated user.",
        "log_tail", "HttpOnly/Secure cookie flags, short session lifetimes, bind sessions to client fingerprints, monitor for session reuse across anomalous locations."),
    "T1550": ("Lateral Movement", "Use Alternate Authentication Material",
        "Adversaries may use alternate authentication material such as password hashes, Kerberos tickets, or web session cookies in order to move laterally within an environment, bypassing normal authentication.",
        "falco", "Credential rotation, restrict token/ticket lifetimes, monitor for authentication using non-standard material."),
    "T1552": ("Credential Access", "Unsecured Credentials",
        "Adversaries may search compromised systems for insecurely stored credentials, such as plaintext files, configuration files, or environment variables, to gain access to accounts and resources.",
        "falco", "Secrets management tooling (vaults), never store plaintext credentials in files/env vars, scan repositories and images for embedded secrets."),
    "T1553": ("Defense Evasion", "Subvert Trust Controls",
        "Adversaries may undermine security controls that limit usage of otherwise potentially unwanted software, such as forging or stealing code-signing certificates.",
        "falco", "Enforce code-signing verification, restrict trusted certificate stores, monitor for unusual certificate installation."),
    "T1555": ("Credential Access", "Credentials from Password Stores",
        "Adversaries may search for common password storage locations, such as password managers or browser-saved credentials, to obtain user credentials.",
        "falco", "Restrict access to password store files, encrypt credential stores at rest, monitor for access to known password-manager storage paths."),
    "T1562": ("Defense Evasion", "Impair Defenses",
        "Adversaries may maliciously modify components of a victim environment to hinder or disable defensive mechanisms, such as disabling security tooling or logging.",
        "falco", "Tamper-protect security agents and logging pipelines, alert on service-stop events for defensive tooling, restrict permissions needed to disable defenses."),
    "T1563": ("Lateral Movement", "Remote Service Session Hijacking",
        "Adversaries may take control of preexisting sessions with remote services, such as SSH, to move laterally without needing to authenticate independently.",
        "falco", "Session timeout enforcement, monitor for session takeover patterns, restrict shared session usage."),
    "T1566": ("Initial Access", "Phishing",
        "Adversaries may send phishing messages to gain access to victim systems, using deceptive emails or messages to trick users into revealing credentials or executing malicious content.",
        "log_tail", "Email filtering and attachment sandboxing, user awareness training, MFA to limit impact of credential phishing."),
    "T1003.008": None,  # already have
    "T1003": ("Credential Access", "OS Credential Dumping",
        "Adversaries may attempt to dump credentials to obtain account login information, typically in the form of hashes or plaintext passwords, from the operating system or software.",
        "falco", "Restrict access to credential stores, use credential guard/hardening features, monitor for known credential-dumping tool behavior."),
    "T1021": None,  # already have
    "T1027": ("Defense Evasion", "Obfuscated Files or Information",
        "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.",
        "falco", "Static/dynamic analysis with deobfuscation capability, monitor for known obfuscation/packer signatures, restrict execution of unsigned obfuscated payloads."),
    "T1029": ("Exfiltration", "Scheduled Transfer",
        "Adversaries may schedule data exfiltration to be performed only at certain times of day or at intervals to blend traffic patterns with normal activity and evade detection.",
        "falco", "Baseline outbound traffic timing patterns, alert on off-hours or interval-regular outbound transfers, egress filtering."),
    "T1036": ("Defense Evasion", "Masquerading",
        "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users or security tools, such as renaming malicious files to match trusted system files.",
        "falco", "File integrity monitoring against known-good hashes, restrict execution from unexpected paths, monitor for process name/path mismatches."),
}

CVES = {
    "CVE-2018-11776": ("Apache Struts2 is vulnerable to a remote code execution flaw when namespace value is not set in an action mapping and results are used with no or wildcard namespace, allowing an attacker to execute arbitrary code via a crafted URL.",
        8.1, "Apache Struts 2.3.x before 2.3.35 and 2.5.x before 2.5.17", ["T1190"]),
    "CVE-2019-11043": ("A flaw in PHP-FPM (commonly fronted by Nginx) allows an integer underflow leading to memory corruption, which can be exploited to achieve remote code execution via specially crafted requests.",
        9.8, "PHP-FPM with Nginx, PHP 7.1.x/7.2.x/7.3.x before patched versions", ["T1190", "T1059"]),
    "CVE-2019-14271": ("Docker before 19.03.1 is vulnerable to a flaw in 'docker cp' where a malicious container can cause libnss_dns.so.2 to be loaded from an attacker-controlled path, leading to arbitrary code execution on the host.",
        9.8, "Docker Engine < 19.03.1", ["T1611", "T1068"]),
    "CVE-2020-11651": ("SaltStack Salt before 2019.2.4 and 3000 before 3000.2 contains an authentication bypass in the salt-master process, allowing unauthenticated attackers to access certain methods.",
        9.8, "SaltStack Salt < 2019.2.4, < 3000.2", ["T1078", "T1190"]),
    "CVE-2020-14882": ("Oracle WebLogic Server contains an easily exploitable vulnerability allowing unauthenticated attackers with network access via HTTP to compromise WebLogic Server, resulting in full takeover.",
        9.8, "Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0", ["T1190"]),
    "CVE-2020-15257": ("containerd's containerd-shim API is improperly exposed to host network containers via an abstract Unix domain socket, potentially allowing a container to interact with the shim's API and escalate privileges on the host.",
        5.2, "containerd < 1.3.9, < 1.4.3", ["T1068", "T1611"]),
    "CVE-2021-3156": ("Sudo before 1.9.5p2 (Baron Samedit) contains a heap-based buffer overflow, exploitable by any local user without authentication, allowing privilege escalation to root.",
        7.8, "sudo < 1.9.5p2", ["T1068"]),
    "CVE-2021-4034": ("Polkit's pkexec (PwnKit) contains a memory corruption vulnerability due to missing argument validation, allowing any unprivileged local user to gain full root privileges.",
        7.8, "polkit pkexec, most Linux distributions before patched versions", ["T1068"]),
    "CVE-2021-22555": ("A heap out-of-bounds write in the Linux kernel's netfilter subsystem allows a local user to escalate privileges to root, exploitable inside a container with the relevant capabilities.",
        7.8, "Linux kernel 2.6.19 through 5.11.x before patched versions", ["T1068", "T1611"]),
    "CVE-2021-26084": ("Atlassian Confluence Server and Data Center contain an OGNL injection vulnerability allowing an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance.",
        9.8, "Confluence Server/Data Center before patched versions in 2021", ["T1190", "T1059"]),
    "CVE-2021-41773": ("A path traversal vulnerability in Apache HTTP Server 2.4.49 allows an attacker to map URLs to files outside the expected document root; when combined with mod_cgi, this can lead to remote code execution.",
        9.8, "Apache HTTP Server 2.4.49", ["T1190", "T1059"]),
    "CVE-2021-44228": ("Apache Log4j2 (Log4Shell) is vulnerable to remote code execution via JNDI lookups from log messages or parameters that attackers can control, when message lookup substitution is enabled.",
        10.0, "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases)", ["T1190", "T1059", "T1210"]),
    "CVE-2021-45046": ("Following the initial fix for CVE-2021-44228 in Apache Log4j 2.15.0, it was found the fix was incomplete in certain non-default configurations, still permitting a denial-of-service or, in some configurations, remote code execution.",
        9.0, "Apache Log4j2 2.15.0", ["T1190", "T1059"]),
    "CVE-2022-0847": ("A flaw in the Linux kernel's pipe handling (Dirty Pipe) allows a local unprivileged user to overwrite data in arbitrary read-only files, enabling privilege escalation.",
        7.8, "Linux kernel 5.8 and later before patched versions", ["T1068"]),
    "CVE-2022-22965": ("Spring Framework (Spring4Shell) is vulnerable to remote code execution via data binding on JDK 9+, exploitable when the application is deployed as a WAR to an Apache Tomcat container.",
        9.8, "Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19 and earlier, running on JDK 9+", ["T1190", "T1059"]),
    "CVE-2022-29217": None,  # already have real/placeholder version
}

skipped_tech = []
for tid, data in TECHNIQUES.items():
    if data is None:
        skipped_tech.append(tid)
        continue
    tactic, name, desc, source, mitigation = data
    sig = {"log_tail": None, "falco": None}
    if source == "log_tail":
        sig["log_tail"] = {
            "event_type": "generic_activity",
            "match_fields": {},
            "pattern": f"pattern indicative of {name} (distractor placeholder -- not lab-verified)",
            "detector_ref": None,
        }
    else:
        sig["falco"] = {
            "rule_name": None,
            "rule_file": None,
            "trigger_condition": f"condition indicative of {name} (distractor placeholder -- not lab-verified)",
        }
    record = {
        "_reconstructed_note": RECON_NOTE_TECH,
        "id": tid,
        "tactic": tactic,
        "technique_name": name,
        "description": desc,
        "detection_signatures": sig,
        "related_cves": [],
        "mitigation": mitigation,
        "scenario_refs": [],
        "is_scenario_critical": False,
        "sub_technique_of": tid.split(".")[0] if "." in tid else None,
        "platforms": ["Linux", "Containers"],
        "data_sources": [],
    }
    with open(os.path.join(OUT_TECH, f"{tid}.json"), "w") as f:
        json.dump(record, f, indent=2)

skipped_cve = []
for cid, data in CVES.items():
    if data is None:
        skipped_cve.append(cid)
        continue
    desc, score, component, related = data
    record = {
        "_reconstructed_note": RECON_NOTE_CVE,
        "cve_id": cid,
        "description": desc,
        "cvss_score": score,
        "affected_component": component,
        "related_technique_ids": related,
        "lab_planted": False,
        "cwe_ids": [],
        "cvss_vector": "",
        "published_date": "",
        "scenario_refs": [],
        "patch_reference": "",
    }
    with open(os.path.join(OUT_CVE, f"{cid}.json"), "w") as f:
        json.dump(record, f, indent=2)

print(f"Wrote {len(TECHNIQUES) - len(skipped_tech)} technique files (skipped {skipped_tech} -- already real/placeholder)")
print(f"Wrote {len(CVES) - len(skipped_cve)} CVE files (skipped {skipped_cve} -- already real/placeholder)")
