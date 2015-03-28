#!/usr/bin/env python
#Author: DiabloHorn http://diablohorn.wordpress.com
#Demonstrates how to introduce 2FA into a hash
#Hopefully adding an additional layer to further slow down hash cracking
#The 'added value' of this depends highly on how it's setup in a real live environment

import sys
import hashlib
#git clone https://github.com/ricmoo/pyscrypt
#sudo python setup.py install
import pyscrypt
#sudo pip install pyotp
import pyotp

#S3cretP4ssword
USER_PASSWORD = "6b083e5741b742a6ddfc0fdd730eddfab739c9b3e920f7f8584fb289cce0d7c0a76aed147e9cf90f73ff64031a9e9c9fc0442a79a22569f56e70ee980d3836b0"

ROTATING_USER_PASSWORD = ""
#import pyotp
#pyotp.random_base32()
OTP_SECRET = "J62FVR6XXRNRXS4S"

GLOBAL_TOTP = pyotp.TOTP(OTP_SECRET)

def secure_password(password):
    """
    Imitate code which has a hardcoded "pepper"
    Returns the 'peppered' password
    """
    hardcoded_pepper = "global_pepper"
    intermediate_password = password_hash(password, hardcoded_pepper)
    return intermediate_password

def hash_user_password(password):
    """
    Imitates the normal hashing of a user password
    """    
    hardcoded_peruser_salt = "peruser_salt"
    return password_hash(secure_password(password), hardcoded_peruser_salt)
    
def password_hash(plainpassword,passwordsalt):
    """
    Imitate code which receives the password and pepper then
    continous to hash them securely using a per user salt and a sound algorithm
    """
    hashed = pyscrypt.hash(password = plainpassword, salt = passwordsalt, N = 1024, r = 1, p = 1, dkLen = 64)
    return hashed.encode('hex')

def otp_rotate_hash():
    """
    Imitates a separate process which mixes 2FA into the hash
    """
    current_otp_token = str(GLOBAL_TOTP.now())
    return password_hash(USER_PASSWORD, current_otp_token)

def otp_input_hash(password, otp_token):
    """
    Hashes the submitted user password with the provided otp token
    """
    return password_hash(password, otp_token)
        
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "%s <password> <otp>" % sys.argv[0]
        sys.exit()
        
    user_password = sys.argv[1]
    user_otp_token = sys.argv[2]    
    
    """
    Start of adding 2FA to hash
    this would normally run in the background, changing the hash every 30s
    """
    ROTATING_USER_PASSWORD = otp_rotate_hash()
    """
    End of adding 2FA to hash
    """
    
    """
    Hash the password mixing in the 2FA token which was also supplied by the user.    
    """
    user_password_hash = otp_input_hash(hash_user_password(user_password), user_otp_token)
    if user_password_hash == ROTATING_USER_PASSWORD:
        print "Current password hash: "
        print "%s" % ROTATING_USER_PASSWORD
        print "Login OK"
    else:
        print "Current password hash: "
        print "%s" % ROTATING_USER_PASSWORD       
        print "Login Failed"
