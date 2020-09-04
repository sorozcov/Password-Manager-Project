# Universidad del Valle de Guatemala
# Cifrado de información 2020 2
# Grupo 7
# Implementación CCM

import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

##  Se utiliza get_random_bytes para generar la llave para cifrar y descifrar el mensaje
##  Se utiliza el MODE_CCM de AES para cifrar y descifrar el mensaje 
##  Se utiliza un nonce fijo que cambia dependiendo del key. Este debe ser único para la combinación de mensaje / clave. 
##      Para AES, su longitud varía de 7 a 13 bytes, pero la biblioteca crea un nonce aleatorio de 11 bytes (el tamaño máximo de mensaje es de 8 GB).


def encryption(header, data, key):
    cipher = AES.new(key, AES.MODE_CCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
    return json.dumps(dict(zip(json_k, json_v)))

def decryption(json_input, key):
    try:
        b64 = json.loads(json_input)
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = {k:b64decode(b64[k]) for k in json_k}
        cipher = AES.new(key, AES.MODE_CCM, nonce=jv['nonce'])
        cipher.update(jv['header'])
        message = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        return "El mensaje era: " + message.decode("utf-8")
    except:
        return "Error al descifrar el mensaje"

header = b"header"
data = b"Mensaje secreto"
key = get_random_bytes(16)
encryptedMessage = encryption(header,data,key)
print(encryptedMessage)
decryptedMessage = decryption(encryptedMessage, key)
print(decryptedMessage)