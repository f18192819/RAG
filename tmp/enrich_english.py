"""Give both languages the same source-derived goals and mechanisms."""
import json
from pathlib import Path

FOLDER=Path(__file__).resolve().parents[1]/'attack_defense_bot/attack_defense_bot/knowledge'
PREFIX={
'guide-identity':'Manage account creation, job changes and termination so access remains aligned with current responsibilities and accountable business owners.',
'guide-sso':'Single sign-on and federation reduce independent password stores by connecting applications to a trusted identity provider through protocols such as SAML or OpenID Connect.',
'guide-pam':'Privileged access management reduces misuse of administrative privileges through controlled approval, isolated administrative identity and time-limited privileged sessions.',
'guide-mfa':'Multi-factor authentication combines different factor types; phishing-resistant authentication prevents captured credentials or proxy phishing from authenticating to a different origin.',
'guide-password':'Salted, deliberately expensive password hashing raises the cost of offline password guessing after a credential database is stolen.',
'guide-edr':'EDR detects malicious endpoint processes, files and persistence, supports investigation and enables containment such as host isolation.',
'guide-fde':'Full disk encryption protects stored information when a device is lost, stolen or accessed offline, while authorized running sessions still need access controls.',
'guide-csrf':'CSRF protection prevents another site from inducing unwanted state-changing requests through a victim authenticated session.',
'guide-session':'Secure sessions use unpredictable identifiers, renew them after login or privilege changes, and enforce server-side inactivity and absolute timeouts and logout revocation.',
'guide-sca':'Software composition analysis identifies direct and transitive dependencies, versions, known vulnerabilities and license risks; an SBOM records the component inventory.',
'guide-secrets':'Keep application secrets out of source code and distributed configuration by using a controlled vault or workload identity with least-privilege retrieval and audit trails.',
'guide-security-group':'Security groups reduce cloud workload exposure to the internet and unnecessary networks by restricting source, destination, protocol and port to required business flows.',
'guide-container':'Image vulnerability scanning and signature verification identify risky components and reject untrusted images before deployment; runtime isolation and permissions remain necessary.',
'guide-inventory':'Inventory hardware, software and cloud resources with versions, ownership, business purpose and criticality, and continuously reconcile discovery results.',
'guide-ndr':'Network detection and response identifies intrusions, anomalous external communications and lateral movement from traffic, protocol behavior and connection metadata.',
'guide-key':'Manage cryptographic keys across secure generation, distribution, storage, authorized use, rotation, backup, recovery, revocation and destruction.',
'guide-masking':'Tokenization substitutes controlled surrogate identifiers for sensitive values; masking obscures sensitive fields in displays and test datasets.',
'guide-backup':'Isolated or immutable backup copies resist ransomware and accidental deletion, with backup administration separated from production access.',
'guide-retention':'Define retention periods and accountable owners based on business, contractual and applicable legal needs, then securely delete or destroy expired data with evidence.',
'guide-siem':'Central log correlation connects host, network, application and identity events using consistent fields, time and entities to reveal attack chains.',
'guide-ir':'Incident response playbooks define decision authority, coordination, investigation, containment, eradication, recovery and communications for security incidents.',
'guide-risk':'Risk assessment defines scope and criteria, identifies threats and vulnerabilities, evaluates likelihood and impact, and assigns accountable risk owners.',
'guide-change':'Assess the security and business impact of changes, obtain approval, test, schedule deployment and prepare rollback before implementation.',
'guide-ddos':'DDoS defenses maintain network and application availability under abusive traffic while preserving legitimate business access.',
'guide-dns':'DNS monitoring can expose malicious-domain communications, suspicious new domains and DNS tunneling through query and response analysis.',
'guide-cloud-audit':'Cloud audit logs record control-plane API calls, identity activity and resource changes across accounts and regions for attribution and investigation.',
'guide-cloud-iam':'Use resource-, action- and condition-specific grants with workload identities or short-lived credentials, reviewing trust policies and cross-account access.',
'guide-dlp':'DLP identifies and blocks unauthorized exfiltration of sensitive information through endpoint, email, network and cloud channels.',
'guide-sandbox':'Restrict untrusted parsers and code with separate low-privilege execution, file and network access limits, system-call restrictions and resource quotas.',
'guide-time':'Consistent trusted time supports event ordering, cross-system log correlation, certificate validation and token-expiry decisions.'
}

for name in ['control_guides.json','technical_guides.json']:
    path=FOLDER/name;data=json.loads(path.read_text(encoding='utf-8'))
    for doc in data['documents']:
        if doc['id'] in PREFIX:
            prefix=PREFIX[doc['id']]
            if not doc['text_en'].startswith(prefix):doc['text_en']=prefix+' '+doc['text_en']
            doc['text']=doc['text_zh']+'\n'+doc['text_en']
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
print('English notes brought into parity with existing source-derived Chinese notes.')
