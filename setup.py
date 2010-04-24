from distutils.core import setup, Extension

scrypt_module = Extension('scrypt', 
                          sources=['src/scrypt.c',
                                   'scrypt-1.1.6/lib/crypto/crypto_aesctr.c',
                                   'scrypt-1.1.6/lib/crypto/crypto_scrypt-nosse.c',
                                   'scrypt-1.1.6/lib/crypto/sha256.c',
                                   'scrypt-1.1.6/lib/scryptenc/scryptenc.c',
                                   'scrypt-1.1.6/lib/scryptenc/scryptenc_cpuperf.c',
                                   'scrypt-1.1.6/lib/util/memlimit.c',
                                   'scrypt-1.1.6/lib/util/warn.c'],
                          include_dirs=['scrypt-1.1.6',
                                        'scrypt-1.1.6/lib',
                                        'scrypt-1.1.6/lib/scryptenc',
                                        'scrypt-1.1.6/lib/crypto',
                                        'scrypt-1.1.6/lib/util'],
                          define_macros=[('HAVE_CONFIG_H', None)],
                          libraries=['crypto'])

setup(name='scrypt',
      version='0.1.0',
      description='Bindings for the scrypt key derivation function library',
      author='Magnus Hallin',
      author_email='mhallin@gmail.com',
      url='http://bitbucket.org/mhallin/py-scrypt',
      ext_modules=[scrypt_module])
