import pickle
import cryptography
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import string
import getpass

class User:
    def __init__(self, name, msgSalt, pwSalt, encryptedMSG, encryptedPw, Rounds):
        self.name = name
        self.msgSalt = msgSalt
        self.pwSalt = pwSalt
        self.encryptedMSG = encryptedMSG
        self.pw = encryptedPw
        self.Rounds = Rounds
def is_equal(a, b):
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
Userdata = []
try:
    with open('SaveData.pkl', 'rb') as openf:
        Userdata = pickle.load(openf)
        openf.close
except FileNotFoundError:
    pass
allowedChars = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-=!@#$%^&*()_+;:,.<>/?"
CommonPasswords = ""
with open("CommonPasswords.txt", "r") as f:
    CommonPasswords = f.readlines()
    f.close

backend = default_backend()
blindSalt = b'It always comes down to this'
print("Welcome to the vegetating login system. Would you like to login or create a new user. Respond L for login or U for new user: \n")
lOrN = True
while(lOrN):
    response = input('Respond "1" for login or "2" for new user:')
    if (response == "2"):
        #New User
        #new name
        newName = False
        potName = ""
        while ( not newName):
            newName = True
            potName = input("Please input new username here:")
            if(len(potName)> 128):
                print("Please keep usernames shorter than 128 characters")
                newName = False
                continue
            
            for i in potName:
                if(i not in allowedChars):
                    print('Only "%s" allowed', allowedChars)
                    newName = False
            
            if potName in [x.name for x in Userdata]:
                print("Username already taken")
                newName = False
        
        
        
        #new password
        newPass = False
        while( not newPass):
            newPass= True
            password = getpass.getpass(prompt="Please input new password here:")
            if(len(password) < 12 ):
                newPass = False
                print("Please make passwords atleast 12 characters long")
                continue
            hasLower = False
            hasUpper = False
            hasNumber = False
            for i in password:
                if i in string.ascii_lowercase:
                    hasLower = True
                elif i in string.ascii_uppercase:
                    hasUpper = True
                elif i in string.digits:
                    hasNumber = True
            if (hasLower and hasUpper and hasNumber) == False:
                newPass = False
                print("Please have atleast one lowercase, one uppercase and one number in your password")
                continue

            if (password in CommonPasswords):
                newPass = False
                print("Your password is considered too common, please try to make it unique")
                continue
            
        print("You have successfully created a new user. Please enter your secret message:")
        msg = input()
        print("Saving and logging out. Please do not terminate program during this time.")
        msgSalt = os.urandom(16)
        pwSalt = os.urandom(16)
        rounds = 100000+ abs(int.from_bytes(os.urandom(20), byteorder="big"))%100000
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=msgSalt,
            iterations=rounds,
            backend=backend
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        encryptedMsg = f.encrypt(msg.encode())
       
        # kdf2 = PBKDF2HMAC(
        #     algorithm=hashes.SHA3_256(),
        #     length=32,
        #     salt=pwSalt,
        #     iterations=rounds,
        #     backend=backend
        # )
        # # key2 = base64.urlsafe_b64encode(kdf2.derive(password.encode()))
        # # f2 = Fernet(key2)
        # # encryptedPw = f2.encrypt(password.encode())
        curr = password.encode() + pwSalt
        for i in range(rounds):
            digest = hashes.Hash(hashes.SHA3_256(),backend=default_backend())
            digest.update(curr)
            curr = digest.finalize()

        kdf3 = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=blindSalt,
            iterations=rounds,
            backend=backend
        )
        key3 = base64.urlsafe_b64encode(kdf3.derive(password.encode()))
        f3 = Fernet(key3)
        encryptedMsgSalt = f3.encrypt(msgSalt)
        encryptedPwSalt = f3.encrypt(pwSalt)
        Userdata.append(User(potName, encryptedMsgSalt, encryptedPwSalt, encryptedMsg, curr, rounds))
        with open('SaveData.pkl', 'wb') as output:
            pickle.dump(Userdata, output, pickle.HIGHEST_PROTOCOL)
            output.close
        exit()



            
            
    elif(response == "1" ):
        Username = ''
        while(True):
            username = input("Please enter your username:")
            password = getpass.getpass("Please enter your password:")
            isUser = False
            for i in Userdata:
                if(i.name == username ):
                    user = i
                    isUser = True
                    break
            if(isUser == False):
                print("Invalid login details")
                continue
            kdf3 = PBKDF2HMAC(
                algorithm=hashes.SHA3_256(),
                length=32,
                salt=blindSalt,
                iterations=user.Rounds,
                backend=backend
            )
            key3 = base64.urlsafe_b64encode(kdf3.derive(password.encode()))
            f3 = Fernet(key3)
            try:
                pwSalt = f3.decrypt(user.pwSalt)
            except Exception:
                print("Invalid login details")
                continue
            
            curr = password.encode() + pwSalt
            for i in range(user.Rounds):
                digest = hashes.Hash(hashes.SHA3_256(),backend=default_backend())
                digest.update(curr)
                curr = digest.finalize()
            if(curr != user.pw):
                print("Invalid login details")
                continue
            
            print("Successful login.")
            while True:
                action = input('What would you like to do? "1" display secret message, "2" Make a new message (overwrites old message), "3" Log out. :')
                if( action == "1"):
                    msgSalt = f3.decrypt(user.msgSalt)
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA3_256(),
                        length=32,
                        salt=msgSalt,
                        iterations=user.Rounds,
                        backend=backend
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                    f = Fernet(key)
                    decryptedMsg = f.decrypt(user.encryptedMSG)
                    print(decryptedMsg.decode())
                elif(action == "2"):
                    print("Please enter your secret message:")
                    msg = input()
                    print("Saving. Please do not terminate program during this time.")
                    msgSalt = os.urandom(16)
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA3_256(),
                        length=32,
                        salt=msgSalt,
                        iterations=user.Rounds,
                        backend=backend
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                    f = Fernet(key)
                    encryptedMsg = f.encrypt(msg.encode())
                    user.encryptedMSG = encryptedMsg
                    user.msgSalt = f3.encrypt(msgSalt)
                elif(action == "3"):
                    print("Logging out. Please do not terminate program during this time.")
                    #print("Userdata len = %d", len(Userdata))
                    with open('SaveData.pkl', 'wb') as output:
                        pickle.dump(Userdata, output, pickle.HIGHEST_PROTOCOL)
                        output.close
                    exit()

exit()


