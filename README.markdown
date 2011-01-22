Python [scrypt][] bindings
==========================

This is a set of [Python][] bindings for the [scrypt][] key derivation function. 

Scrypt is useful when encrypting password as it is possible to specify a
**minimum** amount of time to use when encrypting and decrypting. If, for
example, a password takes 0.05 seconds to verify, a user won't notice the
slight delay when signing in, but doing a brute force search of several
billion passwords will take a considerable amount of time. This is in
contrast to more traditional hash functions such as MD5 or the SHA family
which can be implemented extremely fast on cheap hardware.

Installation
------------

    $ hg clone http://bitbucket.org/mhallin/py-scrypt
    $ cd py-scrypt
    $ python setup.py build
    
    Become superuser (or use virtualenv):
    # python setup.py install

    Run tests after install:
    $ python tests/scrypt-tests.py


If you want py-scrypt for your Python 3 environment, just run the
above commands with your Python 3 interpreter. Py-scrypt supports both
Python 2 and 3.

Usage
-----

The bindings are very simple -- there is an encrypt and a decrypt method on
the scrypt module:

	>>> import scrypt
	>>> data = scrypt.encrypt('a secret message', 'password', 0.1) # This will take at least 0.1 seconds
	>>> data
	'scrypt\x00\r\x00\x00\x00\x08\x00\x00\x00\x01`\xd2\rE\xc5\xd7\xb0\xe7\xb5\x96F\xa8\xcd2\xb2\xab\xbe\xb1\x1b\xbe\xb6\x8c\xb7\x02\xc2\x85\xda6\xff\x97\x18\x8b\x1d?\xe2\x03\xfe\xeb\x08@O5\xe0q\xea\xb8{\xacQ\x968c\x1c\x1e<\x98K\xca\xccrcr\x04\x17\xe8\xec\xc68\x87m\x89\xae\xd6#C&\x97\xab\x82\x8a\xde\x9b\x0ee\x84\xdb#=\x18\xd7:\xc1\xbc Z\xbe\xd2\xc1\x00\x96\x10\x9a\x16\xb6\xc1\xe6\xef\xdfk\xbe7)\xd6\xf6\xd92\xaat\x11\xfc\xfbIN\x08\xb6\xe3\xcb\x08'
	>>> scrypt.decrypt(data, 'password', 0.1) # This will also take at least 0.1 seconds
	'a secret message'
	>>> scrypt.decrypt(data, 'password', 0.05) # scrypt won't be able to decrypt this data sufficiently fast and an exception is thrown
	Traceback (most recent call last):
	  File "<stdin>", line 1, in <module>
	scrypt.error: decrypting file would take too long
	>>> scrypt.decrypt(data, 'wrong password', 0.1) # scrypt will throw an exception if the password is incorrect
	Traceback (most recent call last):
	  File "<stdin>", line 1, in <module>
	scrypt.error: password is incorrect

One can then make a simple password verifier using the following functions:

	def randstr(length):
	    return ''.join(chr(random.randint(1,254)) for i in range(length))

	def hash_password(password, maxtime=0.5, datalength=64):
	    return scrypt.encrypt(randstr(datalength), password, maxtime)

	def verify_password(hashed_password, guessed_password, maxtime=0.5):
		try:
			scrypt.decrypt(hashed_password, guessed_password, maxtime)
			return True
		except scrypt.error:
			return False

Acknowledgements
----------------

[Scrypt][] was created by Colin Percival and is licensed as 2-clause BSD.
Since scrypt does not normally build as a shared library, I have included
the source for the currently latest version of the library in this
repository. When a new version arrives, I will update these sources.

License
-------

This library is licensed under the same license as scrypt; 2-clause BSD.

[scrypt]: http://www.tarsnap.com/scrypt.html
[Python]: http://python.org
