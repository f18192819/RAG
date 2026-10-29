"""Build reviewed scope annotations from source guides, never development labels.

These annotations describe control classes. They contain no question IDs,
augmentation groups, expected answers, sample organizations or grading rules.
"""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPECS={
 'sso':('application identities;federated authentication','separate application credentials;inconsistent authentication','authentication;access revocation'),
 'identity':('employee accounts;access entitlements','stale accounts;permissions surviving role changes','joiner mover leaver;access review'),
 'pam':('administrator credentials;privileged sessions','shared privileged identities;unaccountable high privilege actions','privileged access approval;temporary elevation'),
 'least':('principals;resource permissions','excessive permissions;unnecessary access','authorization design;access review'),
 'mfa':('authentication factors;account sign-in','phishing;credential replay;password-only authentication','authentication;account recovery'),
 'password':('stored password verifiers','offline password cracking;plaintext password storage','credential storage'),
 'zero':('resource access;user and device context','implicit trust from network location;unrestricted remote access','per-request authorization;continuous verification'),
 'vulnerability':('vulnerability findings;remediation ownership','unprioritized findings;unowned remediation;missing retest','discovery prioritization remediation verification'),
 'patch':('deployed software versions;security updates','outdated software;known exploitable flaws','patch testing;staged deployment;verification'),
 'hardening':('system configurations;secure baselines','insecure defaults;configuration drift','configuration deployment;baseline monitoring'),
 'edr':('endpoint processes;files;host behavior','malicious execution;persistence;credential dumping','detection investigation containment'),
 'fde':('endpoint data at rest;laptop storage;removable storage','lost device;stolen device;offline disk access','storage protection;boot authentication;recovery'),
 'allowlist':('host application execution;scripts;executables','unapproved software execution;unknown binary execution','execution authorization'),
 'sql':('database queries;untrusted application input','input interpreted as SQL syntax','query construction;server-side processing'),
 'xss':('browser output;untrusted content','data interpreted as executable browser script','contextual output encoding'),
 'csrf':('authenticated state-changing requests;browser cookies','cross-origin induced actions;automatic cookie inclusion without request-intent verification','request authorization'),
 'session':('session identifiers;authenticated sessions','session fixation;stale sessions;missing revocation','session creation rotation expiry revocation'),
 'sdlc':('software development lifecycle;engineering process','security omitted from design and delivery;late uncoordinated security work','requirements design implementation release maintenance'),
 'sca':('software components;direct and transitive dependencies','unknown vulnerable dependencies;missing component inventory','dependency inventory;component upgrade assessment'),
 'secrets':('application passwords;API tokens;workload credentials','hardcoded credentials;uncontrolled secret distribution','secret delivery authorization rotation revocation'),
 'cloud-responsibility':('cloud security responsibilities;provider customer roles','unassigned security tasks;incorrect assumptions about provider duties','service design;responsibility allocation'),
 'security-group':('cloud workload network exposure;resource ports','excessive inbound or outbound exposure;publicly reachable management ports','resource network policy configuration'),
 'cspm':('cloud resource configurations;multi-account posture','configuration drift;unnoticed public resources;noncompliant configuration','continuous configuration discovery and remediation'),
 'container':('container images;workloads;orchestration settings','untrusted images;vulnerable components;excessive runtime privileges','image admission;workload deployment;runtime'),
 'inventory':('hardware software and cloud assets;asset owners','unknown assets;missing ownership;unknown versions','asset discovery;inventory maintenance'),
 'segmentation':('network trust zones;inter-zone paths','cross-zone unauthorized access;lateral movement;excessive reachability','network architecture;boundary policy enforcement'),
 'ndr':('network flows;connection metadata;network behavior','anomalous communication;lateral movement;unexpected external connections','network detection investigation containment'),
 'tls':('transport channels;peer certificate identities','peer impersonation;untrusted certificates;insecure transport','connection establishment;certificate verification'),
 'data-classification':('data assets;data owners;handling requirements','unknown sensitivity;inconsistent data handling','data inventory;classification and labeling'),
 'minimization':('personal-data collection;processing purposes','unnecessary collection;processing beyond stated purpose','collection and purpose design'),
 'key':('cryptographic keys;encryption operations','unsafe key storage;uncontrolled key lifecycle','key generation distribution use rotation revocation'),
 'masking':('sensitive data values;nonproduction datasets','unnecessary exposure of real identifiers;reidentification','test data preparation;controlled disclosure'),
 'backup':('recovery copies;backup storage','ransomware alteration;deletion of recovery copies','backup retention;restoration testing'),
 'integrity':('software packages;distributed data;verification keys','unauthorized modification;unverified origin','publication distribution verification'),
 'retention':('data records;identity documents;storage media','obsolete retained data;expired retention;unverified deletion','retention expiry;secure disposal'),
 'supplier':('data-processing contracts;processor obligations','missing security obligations;audit and incident terms absent','contract formation;processing agreement'),
 'transfer':('international personal-data transfers;recipients','unassessed destination and recipient safeguards','transfer assessment;authorization'),
 'dpia':('planned high-risk personal-data processing;data-subject rights','unassessed privacy impacts;large-scale sensitive processing risk','predeployment necessity proportionality and risk assessment'),
 'notification':('incident notifications;privacy-breach reporting','missing escalation;unprepared notifications;unrecorded notification decisions','incident classification and reporting'),
 'siem':('security logs;correlated events','fragmented logs;unlinked security signals','event collection correlation investigation'),
 'ir':('incident response decisions;evidence;recovery coordination','uncoordinated containment;unclear incident authority','preparation detection containment eradication recovery lessons'),
 'risk':('business assets;threats;security investments','priorities detached from likelihood and business impact','risk identification estimation treatment review'),
 'awareness':('human security behavior;role-relevant learning','unsafe repeated behavior;training attendance without behavioral improvement','learning practice feedback and effectiveness measurement'),
 'third-party':('suppliers;outsourced services;supply-chain relationships','unassessed supplier risk;uncontrolled supplier access','supplier selection monitoring and exit'),
 'recovery':('business services;critical dependencies;recovery objectives','unvalidated continuity;unmet recovery time and point objectives','continuity planning;recovery exercises'),
 'change':('production changes;approved configuration state','unauthorized changes;missing rollback or accountability','change approval testing deployment rollback'),
 'ddos':('network and application availability;resource capacity','traffic flooding;resource exhaustion','upstream mitigation;rate limiting;availability protection'),
 'dns':('DNS queries;resolvers;name-service metadata','DNS-specific anomalies;malicious name resolution;DNS tunneling','DNS protection monitoring and investigation'),
 'cloud-audit':('cloud control-plane events;administrative activity logs','missing cloud audit coverage;erasable administrative evidence','cloud audit collection and protected retention'),
 'cloud-iam':('cloud principals;cloud policy permissions','overbroad cloud roles;excessive cloud resource access','cloud authorization;policy review'),
 'cloud-kms':('cloud encryption keys;managed cryptographic operations','unprotected cloud keys;uncontrolled decryption permissions','managed key generation use rotation revocation'),
 'dlp':('sensitive data in motion;outbound files;sharing channels','unauthorized outbound upload;email exfiltration;unapproved cloud transfer','data movement inspection and enforcement'),
 'rest-encryption':('stored database files;snapshots;backups','plaintext exposure after storage disclosure','storage encryption and key separation'),
 'host-backup':('host operating systems;host configurations;host data','unrestorable host state;unverified host backups','host backup and restore testing'),
 'rbac':('business roles;role permissions;user-role assignments','unstructured entitlements;inconsistent role-based access','role design and entitlement review'),
 'endpoint-privilege':('local operating-system privileges;endpoint user accounts','standing local administrator access;unnecessary elevated capabilities','endpoint administration;controlled elevation'),
 'sast-dast':('source code;built artifacts;running applications','security defects found late;insufficient automated application testing','development pipeline;static and dynamic testing'),
 'memory':('parser implementations;memory operations;untrusted binary input','out-of-bounds access;use-after-free;memory corruption','new implementation or rewrite;defect-class prevention'),
 'sandbox':('runtime components;untrusted code or document processing','untrusted execution impact;excessive runtime capabilities','runtime containment;existing component isolation'),
 'secure-boot':('boot chain;firmware and bootloader authenticity','untrusted boot components;modified boot code','boot-time trust verification'),
 'firmware':('device firmware updates;firmware version state','unsigned updates;vulnerable firmware;unsafe rollback','signed update delivery;controlled installation and recovery'),
 'random':('security tokens;nonces;cryptographic random values','predictable security values;insufficient entropy','cryptographic random generation'),
 'time':('system clocks;security timestamps;validity intervals','clock drift;inconsistent event order;incorrect validity decisions','trusted time synchronization and monitoring'),
}
PAIRS=[('fde','dlp'),('dlp','minimization'),('sandbox','memory'),('segmentation','security-group'),
       ('awareness','mfa'),('csrf','session'),('dpia','minimization'),('allowlist','endpoint-privilege'),
       ('secrets','cloud-kms'),('secrets','key'),('firmware','secure-boot')]


def main():
    folder=ROOT/'attack_defense_bot/attack_defense_bot/knowledge'
    docs=[]
    for name in ['control_guides.json','technical_guides.json']:
        docs.extend(json.loads((folder/name).read_text(encoding='utf-8'))['documents'])
    scopes={}
    for doc in docs:
        protected,failures,lifecycle=SPECS[doc['id'].removeprefix('guide-')]
        scopes[doc['id']]={'title':doc['title'],'protected_objects':protected.split(';'),
            'failure_modes':failures.split(';'),'lifecycle_stages':lifecycle.split(';'),
            'primary_mechanisms':[sentence.strip() for sentence in doc['text_en'].split('. ') if sentence.strip()],
            'deployment_assumptions':[],'not_primary_when':[],'confusable_with':{},'source':doc['source']}
    for left,right in PAIRS:
        for own,other in [(left,right),(right,left)]:
            a,b=scopes['guide-'+own],scopes['guide-'+other]
            a['confusable_with']['guide-'+other]={'choose_this_when':a['failure_modes'],
                                                 'choose_other_when':b['failure_modes']}
            a['not_primary_when'].extend(b['failure_modes'])
    scopes['guide-memory']['deployment_assumptions']=['implementation can be changed; prevention of implementation defects is requested']
    scopes['guide-sandbox']['deployment_assumptions']=['runtime isolation is available; containment does not repair implementation defects']
    scopes['guide-security-group']['deployment_assumptions']=['a workload network policy or cloud resource boundary is relevant']
    payload={'schema_version':1,'provenance':'Reviewed annotations of the cited source guides; no evaluation data used.','controls':scopes}
    (folder/'control_scope.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Structured source scopes:',len(scopes))

if __name__=='__main__':main()
