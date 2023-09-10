#!/usr/bin/python

# from ccavutil import encrypt,decrypt
from string import Template


from Crypto.Cipher import AES
import md5

def pad(data):
	length = 16 - (len(data) % 16)
	data += chr(length)*length
	return data

def encrypt(plainText,workingKey):
    	iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
	plainText = pad(plainText)
    	encDigest = md5.new ()
    	encDigest.update(workingKey)
    	enc_cipher = AES.new(encDigest.digest(), AES.MODE_CBC, iv)
    	encryptedText = enc_cipher.encrypt(plainText).encode('hex')
    	return encryptedText



def decrypt(cipherText,workingKey):
    iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    decDigest = md5.new ()
    decDigest.update(workingKey)
    encryptedText = cipherText.decode('hex')
    dec_cipher = AES.new(decDigest.digest(), AES.MODE_CBC, iv)
    decryptedText = dec_cipher.decrypt(encryptedText)
    return decryptedText


def res(encResp):
	'''
	Please put in the 32 bit alphanumeric key in quotes provided by CCAvenues.
	'''	 
	workingKey = '588E07A459E6C1C7B2ABA1AA639B1EE8'
	decResp = decrypt(encResp,workingKey)
	data = '<table border=1 cellspacing=2 cellpadding=2><tr><td>'	
	data = data + decResp.replace('=','</td><td>')
	data = data.replace('&','</td></tr><tr><td>')
	data = data + '</td></tr></table>'
	
	html = '''\
	<html>
		<head>
			<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
			<title>Response Handler</title>
		</head>
		<body>
			<center>
				<font size="4" color="blue"><b>Response Page</b></font>
				<br>
				$response
			</center>
			<br>
		</body>
	</html>
	'''
	fin = Template(html).safe_substitute(response=data)
	return fin
