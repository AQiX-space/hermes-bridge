#!/usr/bin/env python3
"""Sign a SHA256-pinned release manifest using an operator-held RSA private key.
Private PEM never enters Git/CI artifacts or Windows client.
Requires cryptography. Use only after malware review and publisher signing.
"""
import argparse, base64, hashlib, json, pathlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def main():
 p=argparse.ArgumentParser();p.add_argument('--binary',type=pathlib.Path,required=True);p.add_argument('--version',required=True);p.add_argument('--url',required=True);p.add_argument('--key',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
 if not a.url.startswith('https://'):p.error('download URL must use HTTPS')
 data={'version':a.version,'url':a.url,'sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest()}
 canonical='\n'.join([data[k] for k in ('version','url','sha256')]).encode('utf8')
 key=serialization.load_pem_private_key(a.key.read_bytes(),password=None)
 signature=key.sign(canonical,padding.PKCS1v15(),hashes.SHA256())
 data['signature']=base64.b64encode(signature).decode()
 a.output.write_text(json.dumps(data,separators=(',',':'))+'\n')
 print('Signed',data['version'],data['sha256'])
if __name__=='__main__':main()
