"""Starting verdicts on the shipped, non-benign findings. r = real, f = false positive, u = unsure.
Each is a judgement from reading the code around the finding. Keyed by project, file name and line."""
import json, os
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
R = {('python-rsa','cli.py',79):'r',('python-ecdsa','ecdsa.py',327):'r',('python-ecdsa','ecdh.py',123):'r',
 ('python-jose','cryptography_backend.py',209):'r',('authlib','jwe_algs.py',329):'r',('authlib','client_auth.py',148):'r',
 ('authlib','rsa.py',15):'r',('authlib','rsa.py',21):'r',('authlib','ec_key.py',102):'r',('authlib','rsa_key.py',95):'r',
 ('paramiko','pkey.py',390):'u',('paramiko','config.py',449):'f',('paramiko','hostkeys.py',294):'f',('paramiko','hostkeys.py',299):'f',
 ('paramiko','kex_curve25519.py',30):'r',('paramiko','kex_curve25519.py',45):'r',('paramiko','ecdsakey.py',268):'r',
 ('paramiko','ecdsakey.py',305):'r',('paramiko','kex_ecdh_nist.py',59):'r',('paramiko','rsakey.py',188):'r',
 ('pycryptodome','PEM.py',90):'r',('pycryptodome','HPKE.py',183):'r',('itsdangerous','signer.py',45):'r',
 ('certbot','account.py',70):'f',('certbot','ocsp.py',100):'f',('certbot','crypto_util.py',264):'r',('certbot','client.py',199):'r',
 ('certbot','crypto_util.py',274):'r',('django','hashers.py',665):'r',('django','_functions.py',414):'f',
 ('django','_functions.py',460):'f',('django','cached.py',96):'f',('django','crypto.py',49):'r'}
d = json.load(open('web/data/findings.json'))
rev, todo = {}, []
for r in d['repos']:
    for x in r['rep']['findings']:
        if x['scope'] == 'source' and x['clock'] != 'benign':
            k = (r['name'], x['file'].split('/')[-1], x['line'])
            if k in R: rev[f"{r['name']}@{r['version']}|{x['file']}|{x['line']}|{x['primitive']}"] = R[k]
            else: todo.append(k)
print('unlabelled', todo)
d['reviews'] = rev
json.dump(d, open('web/data/findings.json', 'w'), separators=(',', ':'))
from collections import Counter
print(Counter(rev.values()))
