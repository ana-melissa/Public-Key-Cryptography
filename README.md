Ana Melissa

Prof. Long

11/21/2021

CSE13S Fall 2021

# Assignment 6
## Public Key Cryptography

This program consists of a key generation program, and encrypting program, and a decrypting program. I used the GMP library because the numbers that are used in the RSA Algorithm are very large. The GMP Library handles large numbers. This program will generate public and private keys. This program uses those public and private keys to encrypt and decrypt any file given. Given a file, this program will encrypt that file and put the cipher encrypted text into a new file. Then, by running the decryption program on the newly encrypted file, you will create the a new file with the original text in it.

# Build
	- randstate.c randstate.h
	- numtheory.c numtheory.h
	- rsa.c rsa.h
	- keygen.c
	- encrypt.c
	- decrypt.c
	- Makefile

Run these commands to build the program:
---
$make clean
---
$make format
---
$make all
---

# Running Program: Key Generation

First, generate your keys. Running (./keygen) will create your public and private keys and their respective files.
	
	-b: This specifies the minimum bits needed for the public modulus n.
	
	-i: This specifies the number of Miller-Rabin iterations for testing primes. The default is 50 iterations.
	
	-n pbfile: This specifies the public key file. The default file is rsa.pub.
	
	-d pvfile: This specifies the private key file. The default is rsa.priv.
	
	-s: This specifies the random seed for the random state initializarion. The default is given by time(NULL).
	
	-v: This enables the verbose output.
	
	-h: This displays a very useful helpful message about the program synopsis and usage.

	-example command line:
		./keygen [-hv] [-b bits] -n pbfile -d pvfile


# Running Program: Encryption

After generating your keys, you can now encrypt a file of your choice. This will take the public key, encrypt your file, and put the cipher text in the output file of your choice.
	
	-i: This specifies the input file to encrypt. The default file is stdin.

	-o: This specifies the output file to encrypt. The default is stdout.

	-n: This specifies the file containing the public key. The default is rsa.pub.

	-v: This enables the verbose output.

	-h: This displays a very helpful message about the program and the synopsis.
	
	-example command line:
		./encrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey
 

# Running Program: Decryption
After you have encrypted your file, you can now decrypt that file using the private key. 
	
	-i: This specifies the input file to decrypt. The default is stdin.

	-o: This specifies the output file to decrypt. The default is stdout.

	-n: This specifies the file containing the private key. The default file is rsa.priv.

	-v: This enables the verbose output.

	-h: This displays program synopsis and usage.

	-example command line:
		 ./decrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey


# Output
After running keygen, you will recieve both your public key and private key. These keys will be located in the specific files you suggested in the command line. If you didn't specify specific files, the keys will be located in the default files rsa.pub and rsa.priv.

After running encrypt, you will receive an encryption of your input file that you specified. This encryption will be located in the output file you specified in the command line. The default will be stdout.

After running decrypt and reading in the specified encrypted message, you will beable to see the encrypted message decrypted in the specificed output file. This means you will see what was in the original file. This decrypted message will be located in the output file you specified in the command line. The default is stdout.






