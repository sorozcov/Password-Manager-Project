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
import random
import string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import pickle
import binascii

# References
# https://www.youtube.com/watch?v=w68BBPDAWr8&ab_channel=Computerphile


# ---------------------------------------------------------------------------- #
#                    Functions For Reading and Writing Files                   #
# ---------------------------------------------------------------------------- #
#Funtion to read files
def readFile(fileName, encode=False):
    filetxt = ''
    file = open(fileName, "r")
    for line in file.readlines():
        filetxt += line
    file.close()
    if encode:
        filetxt=filetxt.encode('latin-1')
    filetxt=binascii.unhexlify(filetxt)
    
    return filetxt

#Funtions to write files
def writeFile(fileName, text, decode=False):
    text=binascii.hexlify(text)
    if decode:
        text=text.decode('latin-1')
    f = open(fileName, "w")
    f.write(text)
    f.close()

#Funtion to read an object in files
def readObjectInFile(fileName,encode=True):
    fileTxt = readFile(fileName,encode)
    newObject = pickle.loads(fileTxt)
    return newObject
    
#Funtion to write an object in files
def writeObjectInFile(fileName, objectToWrite,decode=True):
    objTxt= pickle.dumps(objectToWrite)
    writeFile(fileName,objTxt,decode)
    return True


# ---------------------------------------------------------------------------- #
#                     Class Key Chain for Password Manager                     #
# ---------------------------------------------------------------------------- #

# Class KeyChain to use a password manager.
# It works like KeePass or Lastpass
# It takes care of all your passwords
# It uses Pycryptome
class KeyChain(object):
    # Inititalize function init
    # masterPassword use to encrypt and decrypt aplication-password
    def __init__(self):
        self.reset()
        self.resetFiles()

    def reset(self):
        self.authenticated=False
        self.passwords=None
        self.vaultKey=None
        self.masterPassword=None
        self.authenticationKey=None
        self.saltPassword=None
        self.hashRealTime=None

    def resetFiles(self):
        self.filePass=None
        self.fileAuth=None
        self.fileSha = None

    def init(self,masterPassword):
        if(len(masterPassword)>64 or len(masterPassword)<1):
            return False, "La contraseña tiene que tener entre 1 y 64 caracteres."
        #Assign our masterPassword
        self.masterPassword=masterPassword
        self.saltPassword = ''.join((secrets.choice(string.ascii_letters) for i in range(64))) 
        self.vaultKey = self.pbkdf2Password(self.masterPassword)
        self.authenticationKey = self.pbkdf2Password(self.masterPassword + self.vaultKey.decode('latin-1'))
        self.passwords={}
        self.authenticated=True
        self.saveHashRealTime()
        return [True]

    #pdkf2Password that is used
    def pbkdf2Password(self,password):
        #We initialize our PBKDF2 password
        #More iterations count, more secured hashed password but more time and less efficiency on algorithm
        iterationCount=5000
        dkLen=32
        prf="sha256"
        #We apply pbkdf2 to our params to get a derivedKey
        return pbkdf2_hmac(prf, password.encode('latin-1'), self.saltPassword.encode('latin-1'), iterationCount, dkLen)

    # Load a KeyChain
    def load(self,masterPassword,representationCipherFile,trustedDataCheckFile,authenticationFile):
        # Read the authenticationFile
        try:
            authentication = readObjectInFile(authenticationFile)
            self.saltPassword = authentication['saltPassword']
        except binascii.Error:
            self.reset()
            return False, "Error. El archivo de autenticación ha sido alterado."
        

        # First we verify masterPassword
        self.masterPassword = masterPassword
        self.vaultKey = self.pbkdf2Password(self.masterPassword)
        self.authenticationKey = self.pbkdf2Password(self.masterPassword + self.vaultKey.decode('latin-1'))

        # Generate the sha256 of the representationCipherFile
        try:
            applicationHashMac = HMAC.new(key=self.vaultKey, digestmod=SHA256, msg= readFile(fileName=representationCipherFile, encode=True))
        except binascii.Error:
            self.reset()
            return False, "Error. El archivo de las contraseñas ha sido alterado."
        applicationHash = applicationHashMac.digest()
        
        # Read the trusted hash file 
        try:
            trustedHash = readFile(fileName=trustedDataCheckFile, encode=False) 
        except binascii.Error:
            self.reset()
            return False, "Error. El archivo del Sha265 ha sido alterado."
        
        #Decrypt representationCipher to have the decrypt
        if(self.authenticationKey == authentication['authenticationKey'].encode('latin-1')):
            #Trusted data check hash is hash representation cipher
            if(applicationHash == trustedHash):
                self.authenticated=True
                self.passwords= readObjectInFile(fileName=representationCipherFile)
                self.saveHashRealTime()
                return [True]
            else:
                #There could be a possible rollback or swap
                self.reset()
                return False, "Error. Podría haber un posible ataque rollback o swap."
        else:
            # Master Password is wrong
            self.reset()
            return False, "La contraseña maestra es incorrecta."

    #Function to save keyChain files
    def saveKeyChain(self,representationCipherFileName,trustedDataCheckFileName,authenticationFileName):
        serializedPassword,hashPassword=self.dump()
        #Write all files with key chain information
        writeFile(fileName=representationCipherFileName,text=serializedPassword,decode=True)
        
        writeFile(fileName=trustedDataCheckFileName,text=hashPassword,decode=True)
        authentication={
            'authenticationKey':self.authenticationKey.decode('latin-1'),
            'saltPassword':self.saltPassword,
        }
        writeObjectInFile(fileName=authenticationFileName,objectToWrite=authentication)


    # Returns serialized passwordsObject and it's respective hash
    def dump(self):
        serializedPasswords = pickle.dumps(self.passwords)
        passwordsHashMac = HMAC.new(key=self.vaultKey, digestmod=SHA256,msg=serializedPasswords)
        passwordsHash = passwordsHashMac.digest()
        return serializedPasswords,passwordsHash

    # Generates a the value to add to the passwordManager
    def set(self,application, password):
        #Throw exception if not authenticated
        if(not self.authenticated):
            return False, 'Error. El usuario no esta autenticado.'
        if(not self.verifySwapAndRollbackAttack()):
            return False, 'Error. Probable ataque de swap en cambio de data.'
        #Check if password length
        if(len(password)>64 or len(password)<1):
            return False, "La contraseña tiene que tener entre 1 y 64 caracteres."
        if(len(password)<64):
            password=password.encode('latin-1')
            password=pad(password,64)
        #Only if authenticated
        applicationHashMac = HMAC.new(key=self.vaultKey, digestmod=SHA256,msg=application.encode('latin-1'))
        applicationHash = applicationHashMac.hexdigest()
        cipherPasswords = AES.new(self.vaultKey, AES.MODE_GCM, applicationHashMac.digest())
        passwordEncryptedBytes = cipherPasswords.encrypt(password)
        passwordEncrypted = passwordEncryptedBytes.decode('latin-1')
        self.passwords[applicationHash]=passwordEncrypted
        self.saveHashRealTime()
        return True, "Se agrego la contraseña correctamente", applicationHash


    # Gets the value of password manager
    def get(self,application):
        #Throw exception if not authenticated
        if(not self.authenticated):
            return False, 'Error. El usuario no esta autenticado.'
        if(not self.verifySwapAndRollbackAttack()):
            return False, 'Error. Probable ataque de swap en cambio de data.'
        #Only if authenticated
        applicationHashMac = HMAC.new(key=self.vaultKey, digestmod=SHA256,msg=application.encode('latin-1'))
        applicationHash = applicationHashMac.hexdigest()
        #Check if our password manager has that application
        if(not applicationHash in self.passwords.keys()):
            return False, 'No existe una contraseña para esta aplicación.'
        #If it has the application continue
        cipherPasswords = AES.new(self.vaultKey, AES.MODE_GCM, applicationHashMac.digest())
        passwordDecryptedBytes = cipherPasswords.decrypt(self.passwords[applicationHash].encode('latin-1'))
        passwordDecryptedBytes = unpad(passwordDecryptedBytes,64)
        passwordDecrypted = passwordDecryptedBytes.decode('latin-1')
        
        return True, passwordDecrypted

    # Removes the application of password manager
    def remove(self,application):
        #Throw exception if not authenticated
        if(not self.authenticated):
            return False, 'Error. El usuario no esta autenticado.'
        if(not self.verifySwapAndRollbackAttack()):
            return False, 'Error. Probable ataque de swap en cambio de data.'
        #Only if authenticated
        applicationHashMac = HMAC.new(key=self.vaultKey, digestmod=SHA256,msg=application.encode('latin-1'))
        applicationHash = applicationHashMac.hexdigest()
        #Check if our password manager has that application
        if(not applicationHash in self.passwords.keys()):
            return False, 'La aplicación no ha sido creada.'
        #Remove from password
        del self.passwords[applicationHash]  
        self.saveHashRealTime()
        return True, "Se ha eliminado correctamente la aplicación", applicationHash

    

    #Implementation of swap or rollback attack on real time
    # Swap Attack Simulation
    def swapAttackSimulation(self):
        try:
            #Make a swap between keys as if simulator was able to do it from the database
            if(len(self.passwords)>=2):
                app1, pass1 = random.choice(list(self.passwords.items()))
                app2, pass2 = random.choice(list(self.passwords.items()))
                while(app1==app2):
                    app2, pass2 = random.choice(list(self.passwords.items()))
                self.passwords[app1]=pass2
                self.passwords[app2]=pass1
                return True, 'Se ha simulado el Swap Attack exitosamente.'
            else:
                return False, 'Error. Se necesitan al menos dos aplicaciones con sus contraseñas en la base de datos.'
        except:
            return False, 'Error. Se necesitan al menos dos aplicaciones con susu contraseñas en la base de datos.'
    
    #Verify Hash on Real Time
    def verifySwapAndRollbackAttack(self):
        if(self.hashRealTime==self.dump()[1]):
            #There has been no swap or rollback
            return True
        #There has been a rollback or swap attack
        return False

    #Maintain a real time hash to verify trusted data information
    def saveHashRealTime(self):
       self.hashRealTime=self.dump()[1]




