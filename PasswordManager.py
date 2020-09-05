# ---------------------------------------------------------------------------- #
#                      Universidad del Valle de Guatemala                      #
#                      Cifrado de información 2020 2                           #
#                      Grupo 7                                                 #
#                      KeyChain.py                                             #
# ---------------------------------------------------------------------------- #
# Class using AES GCM to cipher and decipher saved passwords
# Key will be the master password
# Applications will be saved using HMAC(key,applicationName)
# If HMAC exists return password, else return None

# Assume each password will be at most 64 bytes length
# For that we can use PADDING

# MASTER PASSWORD is going to be 64 bytes
# If length is less, we will use PBKDF2 derivation key
# We will onlly call PBKDF2 once as it takes a long and slow time for execution

# Information on document of key pass will be on a serializer of the encryption
# Also there will be a SHA-256 to prevent rollback and swap

# Libraries needed
# Import pbkdf2 Library to Use
from backports.pbkdf2 import pbkdf2_hmac
import secrets
import string




# Class KeyChain to use a password manager.
# It works like KeePass or Lastpass
# It takes care of all your passwords
# It uses Pycryptome
class KeyChain(object):
    
    
    def __init__(self,masterPassword,representationCipher=None,trustedDataCheck=None):
        if(representationCipher==None and trustedDataCheck==None):
            return self.init(masterPassword)
        elif(representationCipher!=None and trustedDataCheck!=None):
            return self.load(masterPassword,representationCipher,trustedDataCheck)
        else:
            #A param might be missing
            return False

    # Inititalize function init
    # masterPassword use to encrypt and decrypt aplication-password
    def init(self,masterPassword):
        if(len(masterPassword)>64 or len(masterPassword)<1):
            print("Password must be between 1 and 64 characters.")
            return False
        #Assign our masterPassword
        self.masterPassword=masterPassword
        self.passwordManager={}
        self.authenticated = True
        self.pbkdf2Password(masterPassword)

    def pbkdf2Password(self):
        #We initialize our PBKDF2 password
        prf="sha256"
        iterationCount=500000
        secure_str = ''.join((secrets.choice(string.ascii_letters) for i in range(64)))
        self.saltPassword = secure_str.encode("utf8")
        
        #More iterations count, more secured hashed password but more time and less efficiency on algorithm
        iterationCount=5000
        dkLen=64
        prf="sha256"
        #We apply pbkdf2 to our params to get a derivedKey
        self.derivedKey = pbkdf2_hmac(prf, self.masterPassword.encode("utf8"), self.saltPassword, iterationCount, dkLen)

    # Load a KeyChain
    def load(self,masterPassword,representationCipher,trustedDataCheck):
        # First we verify masterPassword
        # First line in code will have the password encrypted
        if(masterPassword):
            #self.masterPassword = masterPassword decrypted
            #self.passwordManagerEncrypted = representationCipher decrypted
            self.pbkdf2Password(masterPassword)
            self.passwordManagerEncrypted = {}
            self.authenticated = True
        else:
            # Master Password is wrong
            return False

    # Generates a cipher of self.passwordManager and the respective self.hashsha256 of self.psswordManager
    def dump(self):
        return True
        #return (self.passwordManager,self.hashsha256)
        #return null if error
    
    # Generates a the value to add to the passwordManager
    def set(application, password):
        #Convert application to hash
        #Encrypt password using GCM and masterPassword
        self.passwordManagerEncrypted[application]=password 

    # Gets the value of password manager
    def get(application):
        #Convert application to hash check if exists
        return None
        #Decrypt password using GCM and masterPassword
        return self.passwordManagerEncrypted[application]

    # Removes the application of password manager
    def remove(application):
        #Convert application to hash check if exists
        return None
        #Decrypt password using GCM and masterPassword
        #Remove from dictionary  