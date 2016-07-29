#!/usr/bin/python
#Program developed by Kavier Koo for personal perposes
import os , binascii, base64, hashlib	

def hextoascii():
	
	print "===================================================================="
	print "			 Hex to ASCII"
	print "===================================================================="
	hexkey = raw_input("Insert hex key\t: ")
	asciikey = binascii.unhexlify(hexkey.replace(r'\x', ''))
	print "\nHex to ASCII\t:",asciikey

def b64():
	
	print "===================================================================="
	print "		  Base 64 Encoder/Decoder"
	print "===================================================================="
	print " 1. Encoder"
	print " 2. Decoder"
	print " 0. Back"
	b64choice = int(input("Insert choice\t: "))
	if (b64choice is 1 ):
		os.system("cls")
		print "===================================================================="
		print "		   Base 64 Encoder"
		print "===================================================================="
		b64encodekey = raw_input("Insert input to Encode\t: ")
		b64encodekey = base64.b64encode(b64encodekey)
		print "\nEncoded Base64 Key\t:",b64encodekey
		
		
	elif (b64choice is 2 ):	
		os.system("cls")	
		print "===================================================================="
		print "		   Base 64 Decoder"
		print "===================================================================="
		b64decodekey = raw_input("Insert input to Encode\t: ")
		b64decodekey = base64.b64decode(b64decodekey)
		print "\nEncoded Base64 Key\t:",b64decodekey
		
	elif (b64choice is 0 ):
		menu()
	else:
		print "Out of range..."
		menu()
	
def hash():
	print "===================================================================="
	print "		  Base 64 Encoder/Decoder"
	print "===================================================================="
	print " 1. MD5"
	print " 2. SHA1"
	print " 3. SHA224"
	print " 4. SHA256"
	print " 5. SHA384"
	print " 6. SHA512"
	print " 0. Back"
	hashchoice = int(input("Insert choice\t: "))
	os.system("cls")
	if (hashchoice is 1 ):
		print "===================================================================="
		print "		   MD5 Hash"
		print "===================================================================="
		md5key = raw_input("Insert input to Encode\t: ")
		md5key = hashlib.md5(md5key.encode())
		print "\nEncoded MD5 Key\t:",md5key.hexdigest()
		
	elif (hashchoice is 2 ):
		print "===================================================================="
		print "		   SHA1 Hash"
		print "===================================================================="
		sha1key = raw_input("Insert input to Encode\t: ")
		sha1key = hashlib.sha1(sha1key.encode())
		print "\nEncoded MD5 Key\t:",sha1key.hexdigest()	
		
	elif (hashchoice is 3 ):
		print "===================================================================="
		print "		   SHA224 Hash"
		print "===================================================================="
		sha224key = raw_input("Insert input to Encode\t: ")
		sha224key = hashlib.sha224(sha224key.encode())
		print "\nEncoded MD5 Key\t:",sha224key.hexdigest()	
		
	elif (hashchoice is 4 ):
		print "===================================================================="
		print "		   SHA224 Hash"
		print "===================================================================="
		sha256key = raw_input("Insert input to Encode\t: ")
		sha256key = hashlib.sha256(sha256key.encode())
		print "\nEncoded MD5 Key\t:",sha256key.hexdigest()	
		
	elif (hashchoice is 5 ):
		print "===================================================================="
		print "		   SHA384 Hash"
		print "===================================================================="
		sha384key = raw_input("Insert input to Encode\t: ")
		sha384key = hashlib.sha384(sha384key.encode())
		print "\nEncoded MD5 Key\t:",sha384key.hexdigest()
		
	elif (hashchoice is 6 ):
		print "===================================================================="
		print "		   SHA512 Hash"
		print "===================================================================="
		sha512key = raw_input("Insert input to Encode\t: ")
		sha512key = hashlib.sha512(sha512key.encode())
		print "\nEncoded MD5 Key\t:",sha512key.hexdigest()	
		
	elif (hashchoice is 0 ):
		menu()
	else:
		print "Out of range..."
		menu()

		
def menu():
	while True:
		os.system("cls")
		print "===================================================================="
		print "			 Converter"
		print "===================================================================="
		print " 1. Hex To ASCII"
		print " 2. Base64 Encoder/Decoder"
		print " 3. Hash"
		print " 0. Exit"
		choice = int(input("Insert choice\t: "))
		os.system("cls")
		if (choice is 1 ):
			hextoascii()	
			raw_input("\nInput anything to continue...")
		elif (choice is 2 ):
			b64()
			raw_input("\nInput anything to continue...")
		elif (choice is 3 ):
			hash()
			raw_input("\nInput anything to continue...")
		elif (choice is 0 ):	
			print "Exit"
			exit()
		else:
			print "Out of range..."
			raw_input("\nInput anything to continue...")

while True:
	try:
		menu()
	except Exception as ex:
		print "\n\n===================================================================="
		print "			Something Wrong"
		print "===================================================================="
		print "Error Code\t: ",ex
		raw_input("Input anything to continue...")
		
