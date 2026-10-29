"""Freeze group-disjoint splits before running any new inference experiment."""
from collections import defaultdict
import hashlib
import json
import argparse
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
CONTROLS=['data-classification','dpia','retention','transfer','supplier','notification',
 'patch','allowlist','edr','endpoint-privilege','fde','host-backup','sql','xss','csrf','secrets',
 'sast-dast','sca','segmentation','zero','tls','dns','ndr','ddos','rest-encryption','key','dlp',
 'masking','backup','integrity','cloud-iam','security-group','cspm','cloud-audit','cloud-kms',
 'container','risk','ir','recovery','awareness','third-party','vulnerability','mfa','rbac','pam',
 'sso','identity','zero','secure-boot','memory','sandbox','time','random','firmware']


def hashed(value):return hashlib.sha256(('v28-frozen-20261029:'+value).encode()).hexdigest()


def main():
    target=ROOT/'experiments/v28/splits.json'
    parser=argparse.ArgumentParser();parser.add_argument('--replace-before-run',action='store_true');args=parser.parse_args()
    if target.exists() and (not args.replace_before_run or list((ROOT/'experiments/v28/results').glob('*details*'))):
        raise SystemExit('Split manifest already frozen; refusing to regenerate.')
    dataset=ROOT/'public_dataset.jsonl';rows=[json.loads(line) for line in dataset.read_text(encoding='utf-8').splitlines()]
    canonical={'control-'+str(i).zfill(2):'guide-'+name for i,name in enumerate(CONTROLS)}
    groups=defaultdict(list)
    for row in rows:
        if row['expected']['decision']=='answer':groups[canonical[row['provenance']['augmentation_group']]].append(row)
    # Domain-stratified control groups, never paraphrases of one control in two splits.
    domains=defaultdict(list)
    for group,members in groups.items():domains[members[0]['provenance']['domain']].append(group)
    partition={'debug':[],'validation':[],'holdout':[]};sampled={key:[] for key in partition}
    for domain,keys in sorted(domains.items()):
        keys.sort(key=hashed)
        n=max(1,round(len(keys)*0.2))
        for split,chosen in [('holdout',keys[:n]),('validation',keys[n:2*n]),('debug',keys[2*n:])]:
            for group in chosen:
                members=sorted(groups[group],key=lambda row:hashed(row['id']))
                partition[split].extend(row['id'] for row in members)
                short=[row for row in members if row['expected']['answer'] not in {'A','B','C','D'}]
                choice=[row for row in members if row['expected']['answer'] in {'A','B','C','D'}]
                # A predeclared balanced subset per control group; no adaptive selection.
                sampled[split].extend(row['id'] for row in choice[:1]+short[:2])
    manifest={'schema_version':1,'seed':'v28-frozen-20261029','dataset_sha256':hashlib.sha256(dataset.read_text(encoding='utf-8').encode('utf-8')).hexdigest(),
              'group_disjoint':True,'canonical_control_disjoint':True,'prior_public_exposure':True,
              'caveat':'All public data was used in earlier v1-v27 development; this is a frozen regression holdout, not a newly unseen generalization set.',
              'canonical_controls':canonical,'partitions':partition,'evaluation_subset':sampled,
              'attack_ids':[row['id'] for row in rows if row['expected']['decision']=='reject']}
    target.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print({split:{'all':len(partition[split]),'fixed_evaluation':len(sampled[split])} for split in partition})

if __name__=='__main__':main()
