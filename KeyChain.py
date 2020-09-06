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

# References
#https://www.youtube.com/watch?v=w68BBPDAWr8&ab_channel=Computerphile


# Class KeyChain to use a password manager.
# It works like KeePass or Lastpass
# It takes care of all your passwords
# It uses Pycryptome
class KeyChain(object):
    # Inititalize function init
    # masterPassword use to encrypt and decrypt aplication-password
    def init(self,masterPassword):
        if(len(masterPassword)>64 or len(masterPassword)<1):
            print("Password must be between 1 and 64 characters.")
            return False
        #Assign our masterPassword
        self.masterPassword=masterPassword
        self.vaultKey = self.pbkdf2Password(self.masterPassword)
        self.passwords={}
        self.vaultKey = self.pbkdf2Password(self.masterPassword)
        self.authenticationKey = self.pbkdf2Password(self.masterPassword + self.vaultKey)

    def pbkdf2Password(self,password,saltPassword=None):
        #We initialize our PBKDF2 password
        # secure_str = ''.join((secrets.choice(string.ascii_letters) for i in range(64)))
        self.saltPassword ='iEPBCwJhBTlrGcIRSAyaXvKmlhdPnyxFKNjrDJHhQlTjoehyfRHgsRDCSSCdJDUM'  if saltPassword==None else saltPassword 
        #More iterations count, more secured hashed password but more time and less efficiency on algorithm
        iterationCount=5000
        dkLen=64
        prf="sha256"
        #We apply pbkdf2 to our params to get a derivedKey
        return pbkdf2_hmac(prf, password, self.saltPassword, iterationCount, dkLen)

    # Load a KeyChain
    def load(self,masterPassword,representationCipher,trustedDataCheck):
        # First we verify masterPassword
        self.masterPassword = masterPassword
        self.vaultKey = self.pbkdf2Password(self.masterPassword)
        self.authenticationKey = self.pbkdf2Password(self.masterPassword + self.vaultKey)
        #Decrypt representationCipher to have the decrypt
        if(self.authenticationKey==True):
            #Trusted data check hash is hash representation cipher
            if(self.trustedDataCheck==True):
                self.authenticated=True
                #self.passwords= decrypt(representationCipher).toDictionary()
            else:
                self.authenticated = True
        else:
            # Master Password is wrong
            self.authenticated=False
            self.masterPassword=None
            self.vaultKey=None
            self.authenticationKey=None
            return False

    # Generates a cipher of self.passwordManager and the respective self.hashsha256 of self.psswordManager
    def dump(self):
        return True
        #return (self.passwordManager,self.hashsha256)
        #return null if error
    
    # Generates a the value to add to the passwordManager
    def set(self,application, password):
        #Convert application to hash
        #Encrypt password using GCM and masterPassword
        self.passwordManagerEncrypted[application]=password 

    # Gets the value of password manager
    def get(self,application):
        #Convert application to hash check if exists
        return None
        #Decrypt password using GCM and masterPassword
        return self.passwordManagerEncrypted[application]

    # Removes the application of password manager
    def remove(self,application):
        #Convert application to hash check if exists
        return None
        #Decrypt password using GCM and masterPassword
        #Remove from dictionary  



#Generate masterPassword by appending your user and password

# To authenticate we do pdkf2 with the vault key and the password again 5000 on your client authentication key