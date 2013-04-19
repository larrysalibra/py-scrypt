#!/usr/bin/env python
from distutils.core import setup, Extension, Command

import sys
import platform

includes = []
library_dirs = []
cmdclasses = dict()
CFLAGS = []


class Tester(Command):
    """Runs unit tests"""

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        if ((sys.version_info > (3, 2, 0, 'final', 0)) or
            (sys.version_info > (2, 7, 0, 'final', 0) and sys.version_info < (3, 0, 0, 'final', 0))):
            from unittest import TextTestRunner, defaultTestLoader
        else:
            try:
                from unittest2 import TextTestRunner, defaultTestLoader
            except ImportError:
                print("Please install unittest2 to run the test suite")
                exit(-1)
        from tests import test_scrypt, test_scrypt_py2x, test_scrypt_py3x
        suite = defaultTestLoader.loadTestsFromModule(test_scrypt)
        suite.addTests(defaultTestLoader.loadTestsFromModule(test_scrypt_py2x))
        suite.addTests(defaultTestLoader.loadTestsFromModule(test_scrypt_py3x))
        runner = TextTestRunner()
        result = runner.run(suite)

cmdclasses['test'] = Tester

if sys.platform.startswith('linux'):
    define_macros = [('HAVE_CLOCK_GETTIME', '1'),
                     ('HAVE_LIBRT', '1'),
                     ('HAVE_POSIX_MEMALIGN', '1'),
                     ('HAVE_STRUCT_SYSINFO', '1'),
                     ('HAVE_STRUCT_SYSINFO_MEM_UNIT', '1'),
                     ('HAVE_STRUCT_SYSINFO_TOTALRAM', '1'),
                     ('HAVE_SYSINFO', '1'),
                     ('HAVE_SYS_SYSINFO_H', '1'),
                     ('_FILE_OFFSET_BITS', '64')]
    libraries = ['crypto', 'rt']
    CFLAGS.append('-O2')
elif sys.platform.startswith('win32'):
    define_macros = []
    library_dirs = ['c:\OpenSSL-Win32\lib\MinGW']
    libraries = ['eay32']
    includes = ['c:\OpenSSL-Win32\include']
elif sys.platform.startswith('darwin') and platform.mac_ver()[0] < '10.6':
    define_macros = [('HAVE_SYSCTL_HW_USERMEM', '1')]
    libraries = ['crypto']
else:
    define_macros = [('HAVE_POSIX_MEMALIGN', '1'),
                     ('HAVE_SYSCTL_HW_USERMEM', '1')]
    libraries = ['crypto']

scrypt_module = Extension('_scrypt',
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
                                        'scrypt-1.1.6/lib/util'] + includes,
                          define_macros=[('HAVE_CONFIG_H', None)] + define_macros,
                          extra_compile_args=CFLAGS,
                          library_dirs=library_dirs,
                          libraries=libraries)

setup(name='scrypt',
      version='0.6.0',
      description='Bindings for the scrypt key derivation function library',
      author='Magnus Hallin',
      author_email='mhallin@gmail.com',
      url='http://bitbucket.org/mhallin/py-scrypt',
      py_modules=['scrypt'],
      ext_modules=[scrypt_module],
      classifiers=['Development Status :: 4 - Beta',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Programming Language :: Python :: 2.6',
                   'Programming Language :: Python :: 2.7',
                   'Programming Language :: Python :: 3',
                   'Topic :: Security :: Cryptography',
                   'Topic :: Software Development :: Libraries'],
      license='2-clause BSD',
      long_description=open('README.rst').read(),
      cmdclass=cmdclasses)
