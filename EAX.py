# Universidad del Valle de Guatemala
# Cifrado de información 2020 2
# Grupo 7
# Implementación GCM

import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt(header, data, )

header = b"header"
data = b"secret"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
cipher.update(header)
ciphertext, tag = cipher.encrypt_and_digest(data)

json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
result = json.dumps(dict(zip(json_k, json_v)))
print(result)


def decryption(cipher_txt, key):
    # We assume that the key was securely shared beforehand
    try:
        b64 = json.loads(json_input)
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = {k:b64decode(b64[k]) for k in json_k}
    
        cipher = AES.new(key, AES.MODE_EAX, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        print("The message was: " + plaintext)
    except ValueError, KeyError:
        print("Incorrect decryption")