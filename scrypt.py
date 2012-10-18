import imp
import os
import sys

from ctypes import (cdll,
                    POINTER, pointer,
                    c_char_p,
                    c_size_t, c_double, c_int, c_uint64, c_uint32,
                    create_string_buffer)

_scrypt = cdll.LoadLibrary(imp.find_module('_scrypt')[1])

_scryptenc_buf = _scrypt.exp_scryptenc_buf
_scryptenc_buf.argtypes = [c_char_p,  # const uint_t  *inbuf
                           c_size_t,  # size_t         inbuflen
                           c_char_p,  # uint8_t       *outbuf
                           c_char_p,  # const uint8_t *passwd
                           c_size_t,  # size_t         passwdlen
                           c_size_t,  # size_t         maxmem
                           c_double,  # double         maxmemfrac
                           c_double,  # double         maxtime
                           ]
_scryptenc_buf.restype = c_int

_scryptdec_buf = _scrypt.exp_scryptdec_buf
_scryptdec_buf.argtypes = [c_char_p,           # const uint8_t *inbuf
                           c_size_t,           # size_t         inbuflen
                           c_char_p,           # uint8_t       *outbuf
                           POINTER(c_size_t),  # size_t        *outlen
                           c_char_p,           # const uint8_t *passwd
                           c_size_t,           # size_t         passwdlen
                           c_size_t,           # size_t         maxmem
                           c_double,           # double         maxmemfrac
                           c_double,           # double         maxtime
                           ]
_scryptdec_buf.restype = c_int

_crypto_scrypt = _scrypt.exp_crypto_scrypt
_crypto_scrypt.argtypes = [c_char_p,  # const uint8_t *passwd
                           c_size_t,  # size_t         passwdlen
                           c_char_p,  # const uint8_t *salt
                           c_size_t,  # size_t         saltlen
                           c_uint64,  # uint64_t       N
                           c_uint32,  # uint32_t       r
                           c_uint32,  # uint32_t       p
                           c_char_p,  # uint8_t       *buf
                           c_size_t,  # size_t         buflen
                           ]
_crypto_scrypt.restype = c_int

ERROR_MESSAGES = ['success',
                  'getrlimit or sysctl(hw.usermem) failed',
                  'clock_getres or clock_gettime failed',
                  'error computing derived key',
                  'could not read salt from /dev/urandom',
                  'error in OpenSSL',
                  'malloc failed',
                  'data is not a valid scrypt-encrypted block',
                  'unrecognized scrypt format',
                  'decrypting file would take too much memory',
                  'decrypting file would take too long',
                  'password is incorrect',
                  'error writing output file',
                  'error reading input file']

MAXMEM_DEFAULT = 0
MAXMEMFRAC_DEFAULT = 0.5
MAXTIME_DEFAULT = 300.0
MAXTIME_DEFAULT_ENC = 5.0

IS_PY2 = sys.version_info < (3, 0, 0, 'final', 0)


class error(Exception):
    def __init__(self, scrypt_code):
        if isinstance(scrypt_code, int):
            self._scrypt_code = scrypt_code
            super(error, self).__init__(ERROR_MESSAGES[scrypt_code])
        else:
            self._scrypt_code = -1
            super(error, self).__init__(scrypt_code)


def encrypt(input, password,
            maxtime=MAXTIME_DEFAULT_ENC,
            maxmem=MAXMEM_DEFAULT,
            maxmemfrac=MAXMEMFRAC_DEFAULT):
    """encrypt(input, password, maxtime=5.0, maxmem=0, maxmemfrac=0.125): str

    encrypt a string"""

    if IS_PY2 and isinstance(input, unicode):
        raise TypeError('input must be type str')
    if IS_PY2 and isinstance(password, unicode):
        raise TypeError('password must be type unicode')

    if not IS_PY2 and isinstance(input, str):
        input = bytes(input, 'utf-8')
    if not IS_PY2 and isinstance(password, str):
        password = bytes(password, 'utf-8')

    outbuf = create_string_buffer(len(input) + 128)
    result = _scryptenc_buf(input, len(input),
                            outbuf,
                            password, len(password),
                            maxmem, maxmemfrac, maxtime)
    if result:
        raise error(result)

    return outbuf.raw


def decrypt(input, password,
            maxtime=MAXTIME_DEFAULT,
            maxmem=MAXMEM_DEFAULT,
            maxmemfrac=MAXMEMFRAC_DEFAULT,
            encoding='utf-8'):
    """decrypt(input, password, maxtime=300.0, maxmem=0, maxmemfrac=0.5): str

    decrypt a string"""

    outbuf = create_string_buffer(len(input))
    outbuflen = pointer(c_size_t(0))

    if not IS_PY2 and isinstance(password, str):
        password = bytes(password, 'utf-8')

    result = _scryptdec_buf(input, len(input),
                            outbuf, outbuflen,
                            password, len(password),
                            maxmem, maxmemfrac, maxtime)

    if result:
        raise error(result)

    out_bytes = outbuf.raw[:outbuflen.contents.value]

    if IS_PY2 or encoding is None:
        return out_bytes

    return str(out_bytes, encoding)


def hash(password, salt, N=1 << 14, r=8, p=1, size=64):
    """hash(password, salt, N=2**14, r=8, p=1, size=64): str

    compute a scrypt hash of user-selectable length (64 by default)"""

    outbuf = create_string_buffer(size)

    if not IS_PY2 and isinstance(password, str):
        password = bytes(password, 'utf-8')
    if not IS_PY2 and isinstance(salt, str):
        salt = bytes(salt, 'utf-8')

    if r * p >= (1 << 30) or N <= 1 or (N & (N - 1)) != 0 or p < 1 or r < 1:
        raise error('hash parameters are wrong (r*p should be < 2**30, and N should be a power of two > 1)')

    result = _crypto_scrypt(password, len(password),
                            salt, len(salt),
                            N, r, p,
                            outbuf, size)

    if result:
        raise error('could not compute hash')

    return outbuf.raw


__all__ = ['error', 'encrypt', 'decrypt', 'hash']
