# Universidad del Valle de Guatemala
# Cifrado de información 2020 2
# Grupo 7
# Implementación PKDF2.py
# This is a implementation of PKDF2 using backports.pbkdf2 library
# Password-Based Key Derivation Function 2
# References based on this link
# https://cryptobook.nakov.com/mac-and-key-derivation/pbkdf2

#Import the libraries needed
import os, binascii
from backports.pbkdf2 import pbkdf2_hmac
import secrets
import string

# ---------------------------------------------------------------------------- #
#                                    pbkdf2_hmac                               #
# HMAC/PRF to use for each iteration
# password passwd to use for each iteration
# salt to use for first iteration, best options is to pseudorandom generate one 64 bit
# iterationCount number of iterations
# dkLen derivedkey final length
# ---------------------------------------------------------------------------- #

#Generate secure random string for salt
secure_str = ''.join((secrets.choice(string.ascii_letters) for i in range(64)))
salt = secure_str.encode("utf8")
password = "MyP@ssw0rd1!".encode("utf8")
#More iterations count, more secured hashed password but more time and less efficiency on algorithm
iterationCount=500000
dkLen=48
prf="sha256"
#We apply pbkdf2 to our params to get a derivedKey
derivedKey = pbkdf2_hmac(prf, password, salt, iterationCount, dkLen)
#We print derived key in hex data instead of binary
print("Salt:",salt)
print("Password:", password)
print("Iterations Count:", iterationCount)
print("Derived Key Length:", len(derivedKey))
print("Derived key:", binascii.hexlify(derivedKey))