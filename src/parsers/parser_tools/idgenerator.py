# idgenerator.py

import hashlib

__sha_256 = hashlib.new('sha256')

def hash(s):
    """Accepts a character string and returns a SHA 256 digest of 32 hex digits"""
    __sha_256.update(s.encode('utf-8'))
    return __sha_256.hexdigest()

