import getpass
from os import system as cmd
from os import popen
from time import sleep
import time
import os
from colorama import init
init()
from colorama import Fore, Back, Style 
import sys
#from cryptography.fernet import Fernet
import random
import platform
#from clear_screen import clear
from Crypto.PublicKey import RSA 
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from yaspin import yaspin
import threading
import datetime
import string
from random import choice
from Crypto import Random
from os import walk
import glob
from halo import Halo
from itertools import repeat
import hashlib
from time import sleep, perf_counter
import binascii
from progressbar import AnimatedMarker, Bar, BouncingBar, Counter,FormatLabel ,ProgressBar  
from itertools import product
from tqdm import tqdm
import zipfile
import shutil


algorithm = ''  ;password = '' ; mode = '' ; privatekey =''
saveplace = '.' ;publickey = '' ; keylength ='' ; Crhash = ''
HashSalt = '' ;Crackmethod = '' ; Min = None ; Max = None
wordlist = '' ; Chars = '' ; verbose = False ; Zipfile = ''

RED   = "\033[1;31m" 
HASHLIB_Algorithms = ['blake2b', 'sha224', 'sha3_224', 'md5', 'sha3_512', 'sha512', 'sha384', 'blake2s', 'sha3_384',
				'sha256', 'sha1']



def remove(file):
	System = platform.platform().split("-")[0]
	if System=="Windows":
		cmd('del {} > nul 2>&1'.format(file))
	else:
		cmd('rm -rf {} '.format(file))
   




def clear():
    System = platform.platform().split("-")[0]
    if System=='Windows':
        cmd('cls')
    

    elif System=='Linux':
        cmd('clear')


def Clean_Gen_Files():
	temp_folder = 'temp'
	if os.path.exists(temp_folder):
		try:
			shutil.rmtree(temp_folder)
		except:
			pass
	





def fancyDisplay(buffer, color = RED ):
    #sys.stdout.write(color)
    for i in buffer:
    	print(i,end="")
    	time.sleep(0.001)



def SPAN_EQ(text,stop):
	position = 0
	size = 10
	direction = 1
	while True:
	    print("\r{} [{}={}]".format(text, " " * position, " " * (size - position), position), end='')
	    sys.stdout.flush()

	    position += 1 * direction
	    if direction > 0 and position > size - 1:
	        position = size
	        direction = -1
	    elif position < 1:
	        position = 0
	        direction = 1

	    time.sleep(0.1)
	    if stop():
	    	break


def PRGRES_BAR_3(counter,name,stop):
    w = FormatLabel('Processed: %(value)d of  '+str(counter)), BouncingBar()
    widgets = w
    pbar = ProgressBar(widgets=widgets)
    for i in pbar((i for i in range(int(counter)))):
        time.sleep(0.07)
        if stop():
            ERASE_LINE = '\x1b[2K'
            CURSOR_UP_ONE = '\x1b[1A' 
            sys.stdout.write(CURSOR_UP_ONE )
            sys.stdout.write(ERASE_LINE )
            #clear()
            sys.stdout.write('\r')
            if name=='enc':
            	print(Mrakp,'Encryption Completed')
            else:
            	print(Mrakp,'Decryption Completed')
            break


    ERASE_LINE = '\x1b[2K'
    CURSOR_UP_ONE = '\x1b[1A' 
    sys.stdout.write(CURSOR_UP_ONE )
    sys.stdout.write(ERASE_LINE )
    sys.stdout.write('\r')
    if name=='enc':
    	print(Mrakp,'Encryption Completed')
    else:
    	print(Mrakp,'Decryption Completed')
	        
        



def progressBar1(Stop):
	fmt = "Progress: {:>3}% estimated {:>3}s remaining"
	num = 600
	while  True:
		start = perf_counter()
		for i in range(1, num + 1):
		    # Simulate doing a few calculations
		    sleep(0.01)
		    stop = perf_counter()
		    remaining = round((stop - start) * (num / i - 1))
		    print(fmt.format(100 * i // num, remaining), end='\r')
		if Stop():
			ERASE_LINE = '\x1b[2K'
			sys.stdout.write(ERASE_LINE)
			break
	

        


def progressbar02(it=40, prefix="", size=60, file=sys.stdout):
    count = len(it)
    def show(j):
        x = int(size*j/count)
        file.write("%s[%s%s] %i/%i\r" % (prefix, "#"*x, "."*(size-x), j, count))
        file.flush()
        #sys.stdout.write("\033[F")
        CURSOR_UP_ONE = '\x1b[1A' 
        sys.stdout.write(CURSOR_UP_ONE)         

    show(0)
    for i, item in enumerate(it):
        yield item
        show(i+1)
        #sys.stdout.write("\033[F")
        CURSOR_UP_ONE = '\x1b[1A' 
        sys.stdout.write(CURSOR_UP_ONE)       
    file.write("\r")
    file.flush()
    CURSOR_UP_ONE = '\x1b[1A' 
    sys.stdout.write(CURSOR_UP_ONE)       
   



def startprog_(Counter,stop):
     Counter = int(Counter)
     for i in progressbar02(range(Counter), "Progress: ", 40):
        time.sleep(0.07) # any calculation you need
        CURSOR_UP_ONE = '\x1b[1A' 
        sys.stdout.write(CURSOR_UP_ONE)        
        if stop():
            ERASE_LINE = '\x1b[2K'
            sys.stdout.write(ERASE_LINE )
            print('Progress: [########################################] {}/{}'.format(Counter,Counter))
            break





def spinner_01(TEXT,stop):
	ERASE_LINE = '\x1b[2K' 
	print (TEXT+"... \\",end="")
	syms = [Fore.LIGHTCYAN_EX+'\\', Fore.LIGHTCYAN_EX+'|',Fore.LIGHTCYAN_EX+ '/', Fore.LIGHTCYAN_EX+'-']
	bs = '\b'
	animation = '\\-|/'
	while True:
	    for sym in syms:
	        sys.stdout.write("\x1b[96m"+"\b%s" % sym)
	        sys.stdout.flush()
	        time.sleep(0.005)
	    if stop():
	    	#sys.stdout.write(ERASE_LINE)
	    	#CURSOR_UP_ONE = '\x1b[1A' 
	    	#sys.stdout.write(CURSOR_UP_ONE)
	    	print(Style.RESET_ALL) 
	    	break


def Sp_Dots(text,Color,stop):
    loading = True 
    loading_speed = 4  
    loading_string = "." * 6 
    if Color=='red':
        color = "\x1b[31m"
    elif Color=='green':
        color = "\x1b[32m"

    elif Color=='blue':
        color = "\x1b[34m"

    elif Color=='cyan':
        color = "\x1b[36m"

    elif Color=='lred':
        color = "\x1b[91m"

    elif Color=='lcyan':
        color = "\x1b[96m"

    elif Color=='lgreen':
      color =  "\x1b[92m"

    elif Color=='ly':
        color = "\x1b[93m"
    print(text,end="")
    while 1:
        for index, char in enumerate(loading_string):
            sys.stdout.write(color+char) 
            sys.stdout.flush()  
            time.sleep(1.0 / loading_speed)  
        index += 1  
        sys.stdout.write("\b" * index + " " * index + "\b" * index)
        sys.stdout.flush()  # flush the output
        if stop():
        	break


def loadingeq(Text,Color,stop):
    if Color=='red':
        color = Fore.RED

    elif Color=='green':
        color = Fore.GREEN

    elif Color=='blue':
        color = Fore.BLUE

    elif Color=='cyan':
        color = Fore.CYAN

    elif Color=='lred':
        color = Fore.LIGHTRED_EX

    elif Color=='lcyan':
        color = Fore.LIGHTCYAN_EX

    elif Color=='lgreen':
      color =  Fore.LIGHTGREEN_EX

    elif Color=='ly':
        color = Fore.LIGHTYELLOW_EX
         

    spaces = 0 
    print(Text,end="")                                    
    while 1:
        print(color+"\b "*spaces+"=", end="", flush=True) 
        spaces = spaces+1                           
        time.sleep(0.2)    
        #a+=1                        
        if (spaces>5):                             
            print("\b \b"*spaces, end="")           
            spaces = 0  
        if stop():
        	break





def modeshelp():
	h="""---------------------------------------------------------------------
Mode      :       SETTING :          Option :      DESCRIPTION"
---------------------------------------------------------------------

hash      :   hash,password :   hash:md5:sha1:sha3_512 use list HashSalt to Show Avaliable HashSalt : Hashing Password with hashlib algorithms 

hashhmac  :   hash,password :   hash:md5:sha1:sha3_512 use list HashSalt to Show Avaliable HashSalt : Hashing Password with  hashhmac 

enc       :   password,publicKey,privateKey : private.pem ,public.pem path , password to encrypt : encryption Password with Rsa Method before encryption you must generate keys frist form deeper main menu

dec       :   password,publicKey,privateKey : private.pem ,public.pem path , password to decrypt : decryption Password

crackhash : crackmethod,Hash,Hashsalt,wordlist : crackmethod dictionary or bruteforce  ,Hash to crack, Hashsalt md5 sha1 use list HashSalt to show Avaliable Hashsalt ,wordlist if crackmethod dictionary

crackzip : crackmethod,Zipfile,wordlist : crackmethod dictionary or bruteforce  ,Zipfile to crack wordlist if crackmethod dictionary

-------------------------------------------------------------------

crackhash dictionary attack : crackmethod,Hash,Hashsalt,wordlist

crackhash bruteforce attack : crackmethod,Hash,Hashsalt,Min,Max,Chars : Hash to crack ,Hashsalt md5 sha1 , Minimum Password , Maximum Password chars ?d ?? use list chars to show chars

------------------------------------------------------------------
crackzip dictionary attack:  crackmethod,Zipfile,wordlist
crackzip bruteforce attack:  crackmethod,Zipfile,Min,Max,Chars 
------------------------------------------------------------------

crackmethod use in crackhash mode and crackzip mode 

Syntax:
ex hash mode :
------------------
Set mode hash 
Set hash md5
Set password test 
run 
------------------
ex crackhash mode dictionary:
-----------------------------
Set mode crackhash
Set crackmethod dictionary 
Set Hashsalt md5 
Set Hash bfd00edd436b5048006cd7a2c0753c40 
Set wordlist /home/root/Desktop/pwds.txt
run
------------------------------------------
ex crackhash mode bruteforce:
-----------------------------
Set mode crackhash
Set crackmethod bruteforce 
Set Hashsalt md5 
Set Hash bfd00edd436b5048006cd7a2c0753c40 
Set min 8 
Set max 8 
Set chars ?d
run
-------------------------------------------
ex enc mode :
------------------
Set mode enc
Set publickey /root/Desktop/public.pem
Set privatekey /root/Desktop/private.pem
Set password test
run
---------------------------------
ex dec mode :
-------------------
Set mode dec
Set publickey /root/Desktop/public.pem
Set privatekey /root/Desktop/private.pem
Set password encryption password
run
------------------------------

"""
	hfile = open('help.txt','w+')
	hfile.write(h)
	hfile.close()
	cmd('start help.txt')



	





def helpmenu():
	print("------------------------------------------------------")
	print("{:<25}{}".format('COMMANDS','DESCRIPTION'))
	print("------------------------------------------------------")
	print("{:<25}{}".format('Set',"Edit any option, for display it use 'options' command :Syntax Set option Value"))
	print("{:<25}{}".format('options',"Display use options"))
	print("{:<25}{}".format('run',"Running tool"))
	print("{:<25}{}".format('help',"Display helper menu"))
	print("{:<25}{}".format('exit',"Leave program"))
	print("{:<25}{}".format('list',"To List options [HashSalt,modes,crackmethod,chars]"))
	print("{:<25}{}".format('modeshelp ','To Show Modes Full helper '))
	print()

def options():
	f = Fore.MAGENTA+'False'+Style.RESET_ALL
	t = Fore.YELLOW+'True'+Style.RESET_ALL
	print()
	print("---------------------------------------------------------------------")
	print("NAME :       SETTING :          REQUIRED :      DESCRIPTION")
	print("---------------------------------------------------------------------")
	print("mode        : enc:dec:hash     :  {}    Use list modes To Show Modes ".format(t))
	print("password    : password         :  {}    set to encrypt or decrypt and Hashing ".format(t))
	print("hash        : sha1:md5         :  {}    set HashType Use in Hash Mode".format(t))
	print("saveplace   : Default .        :  {}   set to save encryption Password file [enc] Mode".format(f))
	#print("keylength   : digit            :  {}    specify keylength [enc] list to see all key lengths ".format(t))
	print("publickey   : Path             :  {}    public key Path Use in [enc|dec] Modes".format(t))
	print("privatekey  : Path             :  {}    private key Path Use in [enc|dec] Modes".format(t))
	print("Hash :      : Hash To Crack    :  {}    set Hash Use in [crackhash] Mode".format(t))
	print("Hashsalt    : sha512:md5       :  {}    specify Hashsalt To Crack Use in [crackhash] Mode".format(t))
	print("crackmethod : word             :  {}    choice Crack Hash Method [crackhash,crackzip] Mode ".format(t))
	print("wordlist    : Path To wordlist :  {}    wordlist to Crack Hash Use in [crackhash] Mode".format(t))
	print("min         : Minimum Password :  {}    starting password Use in [crackhash] (Bruteforce)   ".format(t))
	print("max         : maximum Password :  {}    ending password Use in [crackhash] (Bruteforce)".format(t))
	print("chars       : ?d:?l:??         :  {}    Choice Password Characters Use List To Show chars (Bruteforce) ".format(t))
	print("verbose     : bool             :  {}   True:False verbose Cracking Passwords Default False set in [crackhash] mode slows down cracking time Recommended False".format(f))
	print("zipfile     : Path             :  {}   Path to zipfile to crack use in [crackzip] mode ".format(t))
	print()






def list(option):

	HashSalt = ['blake2b', 'sha224', 'sha3_224', 'md5', 'sha3_512', 'sha512', 'sha384', 'blake2s', 'sha3_384',
	'sha256', 'sha1']

	Modes = ['enc: encryption Password','dec: decryption Password','hash: Hashing Password','hashhmac: Hashing hmac Password','crackhash: Crack Hash','crackzip:Crack zipfile']


	crackmethod = ['dictionary','bruteforce']
	
	Chars = ['?d digits (0123456789)','?u uppercase (ABCDEFGHIJKLMNOPQRSTUVWXYZ)','?l lowercase (abcdefghijklmnopqrstuvwxyz) ',
	'?l?d lowercase+digits (abcdefghijklmnopqrstuvwxyz0123456789) ','?u?d uppercase+digits (ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789)',
	 '?a lowercase+uppercase+digits+specialcharacters (abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~)' ,
	 '?? printable (0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~)']


	ascii_letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
	ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	digits = '0123456789'
	hexdigits = '0123456789abcdefABCDEF'
	octdigits = '01234567'
	printable = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
	punctuation = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
	whitespace = ' \t\n\r\x0b\x0c'

	if option=="chars":
		print()
		for i in Chars:
			print(i)
		print()
	elif option=='HashSalt':
		for s in HashSalt:
			print(s)
		print()

	elif option=='modes':
		clear()
		print()
		print("----------------------------------------------------------------")
		print("Mode :                : DESCRIPTION")
		print('enc  :                : encryption Password Rsa publickey')
		print('dec  :                : decryption Password')
		print('hash :                : Hashing Password With hashlib algorithms')
		print('hashhmac :            : Hashing Password With hashhmac hashlib algorithms')
		print('crackhash :           : Hash Cracking Using dictionary And Bruteforce Attack')
		print('crackzip  :           : Crack zipfile')
		print("----------------------------------------------------------------")
		
	elif option=='crackmethod':
		print(crackmethod)

	

	


	
def Set(name,setting):
	global password  , algorithm , mode , keylength , saveplace ,  publickey , privatekey,\
	Crhash , HashSalt , wordlist , Crackmethod , Min ,Max , Chars , verbose,Zipfile
	name = name.split(' ')
	
	if name[0] =='password':
		password = setting
		
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Password ==> {}  ".format(password));print()
		
	# mode hashhmac
	elif name[0]=='mode':
		mode = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Mode ==> {}  ".format(mode));print()
	
		#verbose  True
	
	elif name[0]=='hash':
		if setting in HASHLIB_Algorithms:
			algorithm = setting
			print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Hash ==> {}  ".format(algorithm));print()
			
			
	elif name[0]=='privatekey':
		privatekey = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Private Key ==> {}  ".format(privatekey));print()

	elif name[0]=='saveplace':
		saveplace = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Saveplace ==> {}  ".format(saveplace));print()

	elif name[0]=='publickey':
		publickey = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Public key ==> {}  ".format(publickey));print()


	elif name[0]=='keylength':
		keylength = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"keylength ==> {}  ".format(keylength));print()

	elif name[0]=='Hash':
		Crhash = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Hash ==> {}  ".format(Crhash));print()

	elif name[0]=='Hashsalt':
		if setting in HASHLIB_Algorithms:
			HashSalt = setting
			print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"HashSalt ==> {}  ".format(HashSalt));print()
		else:
			print(I,'HashSalt Not Found! List To Show Salt')

	elif name[0]=='wordlist':
		wordlist = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Wordlist ==> {}  ".format(wordlist));print()

	elif name[0]=='crackmethod':
		Crackmethod = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Crack Method ==> {}  ".format(Crackmethod));print()

		
	elif name[0]=='min':
		Min = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Min ==> {}  ".format(Min));print()

	elif name[0]=='max':
		Max = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Max ==> {}  ".format(Max));print()

	elif name[0]=='chars':
		Chars = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Chars ==> {}  ".format(Chars));print()

	elif name[0]=='verbose':
		verbose = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"verbose ==> {}  ".format(verbose));print()

	elif name[0]=='zipfile':
		Zipfile = setting
		print();print(Fore.MAGENTA+"Set "+Style.RESET_ALL+"Zipfile ==> {}  ".format(Zipfile));print()
		

def run(algorithm,PASSWORD,MODE,saveplace,publickey,privatekey,keylength,HashSalt,wordlist,Crackmethod,Min,Max,Chars,Verbose,Zipfile):
	ast='['+Fore.LIGHTCYAN_EX+'*'+Style.RESET_ALL+']'
	if MODE=='hash':
		if algorithm=='blake2b':
			Hasher = hashlib.blake2b(PASSWORD.encode()).hexdigest() 
			print('[+] blake2b Hash')
			print()
			print(Hasher)
		elif algorithm=='sha224':
			Hasher = hashlib.sha224(PASSWORD.encode()).hexdigest() 
			print('[+] sha224 Hash')
			print()
			print(Hasher)
		elif algorithm=='sha3_224':
			Hasher = hashlib.sha3_224(PASSWORD.encode()).hexdigest() 
			print('[+] sha3_224 Hash')
			print()
			print(Hasher)
		elif algorithm=='md5':
			Hasher = hashlib.md5(PASSWORD.encode()).hexdigest() 
			print('[+] md5 Hash')
			print()
			print(Hasher)

		elif algorithm=='sha3_512':
			Hasher = hashlib.sha3_512(PASSWORD.encode()).hexdigest() 
			print('[+] sha3_512 Hash')
			print()
			print(Hasher)

		elif algorithm=='sha512':
			Hasher = hashlib.sha512(PASSWORD.encode()).hexdigest() 
			print('[+] sha512 Hash')
			print()
			print(Hasher)

		elif algorithm=='sha384':
			Hasher = hashlib.sha384(PASSWORD.encode()).hexdigest() 
			print('[+] sha384 Hash')
			print()
			print(Hasher)

		elif algorithm=='blake2s':
			Hasher = hashlib.blake2s(PASSWORD.encode()).hexdigest() 
			print('[+] blake2s Hash')
			print()
			print(Hasher)

		elif algorithm=='sha3_384':
			Hasher = hashlib.sha3_384(PASSWORD.encode()).hexdigest() 
			print('[+] sha3_384 Hash')
			print()
			print(Hasher)

		elif algorithm=='sha256':
			Hasher = hashlib.sha256(PASSWORD.encode()).hexdigest() 
			print('[+] sha256 Hash')
			print()
			print(Hasher)

		elif algorithm=='sha1':
			Hasher = hashlib.sha1(PASSWORD.encode()).hexdigest() 
			print('[+] sha1 Hash')
			print()
			print(Hasher)
		print()




	
	elif MODE=='hashhmac':
		salt = os.urandom(32)
		print()
		print(Mrakp,'Salt ',salt)
		key = hashlib.pbkdf2_hmac(algorithm,PASSWORD.encode('utf-8'), salt, 100000)
		HEX = binascii.hexlify(key)
		Decode = HEX.decode('utf-8')
		print()
		print(Mrakp,'{} Hash'.format(algorithm))
		print(Decode)
		print()
		

    
   
      
	elif MODE =="enc":
		saveplace =saveplace+'\\'
		message = PASSWORD
		message = message.encode('ascii')
	
		Priv  = privatekey
		Pup = publickey
		try:
			pr_key = RSA.import_key(open(Priv, 'r').read())
			pu_key = RSA.import_key(open(Pup, 'r').read())
		except Exception as e :
			print(e)
			sys.exit()

		#print(type(pr_key), type(pu_key))
		#Instantiating PKCS1_OAEP object with the public key for encryption
		cipher = PKCS1_OAEP.new(key=pu_key)
		#Encrypting the message with the PKCS1_OAEP object
		cipher_text = cipher.encrypt(message)
		c = binascii.hexlify(cipher_text)
		Cipher_Text = c.decode('utf-8')
		with open(saveplace+'\\'+'enc_pass.txt','w') as k:
			k.write(Cipher_Text)
		k.close()
		print(ast,'Encrypted Passwords SaveLocation')
		print(Mrakp,saveplace+'\\enc_pass.txt')
		print(Mrakp,'Encrypted Password')
		print();print(Cipher_Text);print()

		#print(Cipher_Text)

	elif MODE=='dec':
		try:
			pr_key = RSA.import_key(open(privatekey, 'r').read())
			pu_key = RSA.import_key(open(publickey, 'r').read())
		except FileNotFoundError:
			print(Mrak,'Error Keys Not Found Check Keys Path!')
			sys.exit()
		#pu_key = RSA.import_key(depu)
		#print(type(pr_key), type(pu_key))
		#Instantiating PKCS1_OAEP object with the public key for encryption
		cipher = PKCS1_OAEP.new(key=pu_key)
		#Encrypting the message with the PKCS1_OAEP object
		cipher_text = PASSWORD
		#print(cipher_text)
		base64_bytes =cipher_text.encode('ascii')
		final = binascii.unhexlify(base64_bytes)
		

		#print(type(final))
		#print(final)
		#input()
		#Instantiating PKCS1_OAEP object with the private key for decryption
		decrypt = PKCS1_OAEP.new(key=pr_key)
		#Decrypting the message with the PKCS1_OAEP object
		decrypted_message = decrypt.decrypt(final)
		print()
		print(Mrakp,'Decrypted Password')
		print();print(decrypted_message.decode('utf-8'));print()

	elif MODE=='crackhash':
		CURSOR_UP_ONE = '\x1b[1A' 
		ERASE_LINE = '\x1b[2K' 
		solved = False

		if Crackmethod=='dictionary':
			readwordlist = open(wordlist, "r").readlines()
			clear()
			print('.............................')
			print('Input Mode -> Dictionary')
			print('Wordlist {} Words({})'.format(wordlist.split('\\')[-1],len(readwordlist)))
			print('Salt -> {}'.format(HashSalt))
			print('Verbose -> {}'.format(verbose))
			#print('Status ... [Running]')
			sys.stdout.write('\rStatus... [Initializing]')
			
			sleep(3)
			sys.stdout.write(ERASE_LINE) 
			#sys.stdout.write("\033[K")
			#sys.stdout.write('\b')
			sys.stdout.write('\rStatus... [Running]')
			print()
			starttime=time.time()
			pwdtries=0
			counter = len(readwordlist)
			#for i in readwordlist:
			for i in tqdm(readwordlist, total=counter, unit="Word"):
			    pwdtries+=1
			    i=i.strip('\n')
			    if HashSalt in HASHLIB_Algorithms:
			        if HashSalt=='blake2b':
			            Hashing = hashlib.blake2b(i.encode()).hexdigest() 
			        elif HashSalt=='sha224':
			            Hashing = hashlib.sha224(i.encode()).hexdigest() 

			        elif HashSalt=='sha3_224':
			             Hashing = hashlib.sha3_224(i.encode()).hexdigest() 


			        elif HashSalt=='md5':
			            Hashing = hashlib.md5(i.encode()).hexdigest() 

			        elif HashSalt=='sha3_512':
			            Hashing = hashlib.sha3_512(i.encode()).hexdigest()

			        elif HashSalt=='sha512':
			            Hashing = hashlib.sha512(i.encode()).hexdigest()

			        elif HashSalt=='sha384':
			            Hashing = hashlib.sha384(i.encode()).hexdigest()

			        elif HashSalt=='blake2s':
			            Hashing = hashlib.blake2s(i.encode()).hexdigest()

			        elif HashSalt=='sha3_384':
			            Hashing = hashlib.sha3_384(i.encode()).hexdigest()

			        elif HashSalt=='sha256':
			            Hashing = hashlib.sha256(i.encode()).hexdigest()

			        elif HashSalt=='sha1':
			            Hashing = hashlib.sha1(i.encode()).hexdigest()


			        


			    else:
			        print(Style.RESET_ALL)
			        print(Mrak,'HashSalt Not Supported! ')
			        input()


			    #Passwords_Try = str(pwdtries)
			    #sys.stdout.write('\rPasswords Tested '+'({})'.format(Passwords_Try)) 
			    #sys.stdout.flush()
			    #sys.stdout.write("\033[F")


			    HASH = PASSWORD
			    if HASH in Hashing:
			      Cracked_Hash = i
			      solved = True
			      crackedhash = open('crackedhash.txt','w+')
			      crackedhash.write(HASH+':'+Cracked_Hash)
			      crackedhash.close()

			      print('\n[+] Hash Cracked!: {}:{} '.format(HASH,Cracked_Hash))
			      break
			    else:
			    	if verbose=='True':
			    		print('Try:'+HASH+':',i)
			    	else:
			      		pass
			closetime = time.time()
			if solved==True:
				sleep(2)
				clear()
				crackedhashfile = open('crackedhash.txt','r').read()
				print('[+] Hash Cracked!: {} '.format(crackedhashfile))
				print()
				print (ast,"Starting Time ",starttime)
				print (ast,"Closing  Time ",closetime)
				print (ast,"Passwords Tried  ",pwdtries)
				print (ast,"Average Speed ",pwdtries/(closetime-starttime));print()

			else:
				print()	
				print(Mrak,"Cracking Failed")
				print (ast,"Starting Time ",starttime)
				print (ast,"Closing  Time ",closetime)
				print(ast,"Reached end of wordlist")
				print (ast,"Passwords Tried  ",pwdtries)
				print (ast,"Average Speed ",pwdtries/(closetime-starttime));print()
				


				
		elif Crackmethod=="bruteforce":
			solved = False
			ascii_letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
			ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
			ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
			digits = '0123456789'
			hexdigits = '0123456789abcdefABCDEF'
			octdigits = '01234567'
			printable = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
			punctuation = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
			whitespace = ' \t\n\r\x0b\x0c'


			if Chars=="?d":
			    chars = digits

			elif Chars=='?u':
			    chars =  ascii_uppercase

			    

			elif Chars=='?l':
			    chars =  ascii_lowercase

			elif Chars=='?l?d':
			    chars =  ascii_lowercase+digits

			elif Chars=='?u?d':
			    chars =ascii_uppercase+digits

			elif Chars=='?a':
			    chars = ascii_lowercase+ascii_uppercase+digits+punctuation

			elif Chars=='??':
			    chars = printable

			else:
			    print('Error: Use List chars To Show characters')

			clear()
			print('.............................')
			print('Input Mode -> Bruteforce')
			print('Input Chars -> {} '.format(Chars))
			print('Min Passwords  :{}'.format(Min))
			print('Max Password :{}'.format(Max))
			print('Salt -> {}'.format(HashSalt))
			print('Verbose -> {}'.format(verbose))
			#print('Status ... [Running]')
			sys.stdout.write('\rStatus... [Initializing]')
			
			sleep(3)
			sys.stdout.write(ERASE_LINE) 
			#sys.stdout.write("\033[K")
			#sys.stdout.write('\b')
			sys.stdout.write('\rStatus... [Running]')
			print()
			starttime=time.time()
			pwdtries=0
			for length in range(int(Min),int(Max)+1): 
			    to_attempt = product(chars, repeat=length)
			    for attempt in to_attempt:
			        x = ''.join(attempt)
			        if HashSalt=='blake2b':
			            h = hashlib.blake2b(x.encode()).hexdigest() 
			        elif HashSalt=='sha224':
			            h = hashlib.sha224(x.encode()).hexdigest() 

			        elif HashSalt =='sha3_224':
			            h = hashlib.sha3_224(x.encode()).hexdigest() 

			        elif HashSalt=="md5":
			             h = hashlib.md5(x.encode()).hexdigest() 

			        elif HashSalt=='sha3_512':
			            h = hashlib.sha3_512(x.encode()).hexdigest() 

			        elif HashSalt=='sha512':
			            h = hashlib.sha512(x.encode()).hexdigest() 

			        elif HashSalt=='sha384':
			            h = hashlib.sha384(x.encode()).hexdigest() 

			        elif HashSalt=='blake2s':
			            h = hashlib.blake2s(x.encode()).hexdigest() 

			        elif HashSalt=='sha3_384':
			            h = hashlib.sha3_384(x.encode()).hexdigest() 

			        elif HashSalt=='sha256':
			            h = hashlib.sha256(x.encode()).hexdigest() 

			        elif HashSalt=='sha1':
			            h = hashlib.sha1(x.encode()).hexdigest() 


			        hashh =  PASSWORD
			        pwdtries+=1 

			        Passwords_Try = str(pwdtries)
			        sys.stdout.write('\rPasswords Tested '+'({})'.format(Passwords_Try)) 
			        #sys.stdout.write("\033[F")

			        if hashh in h:
			            Cracked_Hash = x
			            print('\n')
			            solved = True
			            print('[+] Hash Cracked!: {}:{} '.format(hashh,Cracked_Hash))
			            print()
			            break
			        else:
				        if verbose=='True':
				        	print('Try:'+hashh+':',x)
				        else:
				        	pass

			            
			    if hashh == h:
			        break

			closetime = time.time()
			if solved==True:      			
				print (ast,"Starting Time ",starttime)
				print (ast,"Closing  Time ",closetime)
				print (ast,"Passwords Tried  ",pwdtries)
				print (ast,"Average Speed ",pwdtries/(closetime-starttime))
				print()
			else:
				print()	
				print(Mrak,"Cracking Failed")
				print (ast,"Starting Time ",starttime)
				print (ast,"Closing  Time ",closetime)
				print(ast,"Reached end of Words")
				print (ast,"Passwords Tried  ",pwdtries)
				print (ast,"Average Speed ",pwdtries/(closetime-starttime))
				print()

	elif MODE=='crackzip':
		if Crackmethod=='dictionary':
			solved = False
			# initialize the Zip File object
			zip_file = zipfile.ZipFile(Zipfile)
			ow = open(wordlist, "r").readlines()
			n_words = len(ow)
			print(Mrakp,"Total Passwords To Test:", n_words)
			starttime = time.time()
			pwdtries = 0 
			with open(wordlist, "rb") as wordlist:
			    for word in tqdm(wordlist, total=n_words, unit="word"):
			    	pwdtries+=1
			    	try:
			    		zip_file.extractall(pwd=word.strip())
			    	except:
			    		continue
			    	else:
			    		solved = True
			    		clear()
			    		with open('password.txt','w+') as passfile:
			    			passfile.write(word.decode().strip())
			    			passfile.close()
			    			print()
			    			closetime = time.time()
			    			print(Mrakp,"Password Found:", word.decode().strip())
			    			print()
			    			print (ast,"Starting Time ",starttime)
			    			print (ast,"Closing  Time ",closetime)
			    			print (ast,"Passwords Tried  ",pwdtries)
			    			print (ast,"Average Speed ",pwdtries/(closetime-starttime))
			    			print()
			    			break
			    		

			if solved==False:
				print()	
				print(Mrak,"Password Not Found, Try Other Wordlist")
				print (ast,"Starting Time ",starttime)
				print (ast,"Closing  Time ",closetime)
				print(ast,"Reached end of Words")
				print (ast,"Passwords Tried  ",pwdtries)
				print (ast,"Average Speed ",pwdtries/(closetime-starttime))
				print()


		elif Crackmethod=='bruteforce':
			solved = False
			ascii_letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
			ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
			ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
			digits = '0123456789'
			hexdigits = '0123456789abcdefABCDEF'
			octdigits = '01234567'
			printable = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
			punctuation = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
			whitespace = ' \t\n\r\x0b\x0c'


			if Chars=="?d":
			    chars = digits

			elif Chars=='?u':
			    chars =  ascii_uppercase

			    

			elif Chars=='?l':
			    chars =  ascii_lowercase

			elif Chars=='?l?d':
			    chars =  ascii_lowercase+digits

			elif Chars=='?u?d':
			    chars =ascii_uppercase+digits

			elif Chars=='?a':
			    chars = ascii_lowercase+ascii_uppercase+digits+punctuation

			elif Chars=='??':
			    chars = printable

			else:
			    print('Error: Use List chars To Show characters')




			temp_folder = 'temp'
			if os.path.exists(temp_folder):
				pass
			else:
				os.mkdir(temp_folder)
			file = 'bwordlist.txt'
			temp_file = os.path.join(temp_folder,file)

			starttime = time.time()
			pwdtries=0
			zip_file = zipfile.ZipFile(Zipfile)
			clear()
			stop_threads = False
			t1 = threading.Thread(target = Sp_Dots, args =('Processing','lcyan',lambda : stop_threads, )) 
			t1.start() 
			for length in range(int(Min),int(Max)+1): 
			    to_attempt = product(chars, repeat=length)
			    for attempt in to_attempt:
			        x = ''.join(attempt)
			        with open(temp_file,'a+') as file:
			            file.write(x+'\n')
			    file.close()
			    clear()
			stop_threads = True
			t1.join()
			print('\r')
			Folder = 'temp'
			wordl = 'bwordlist.txt'
			wordlist = os.path.join(Folder,wordl)
	        # initialize the Zip File object
			zip_file = zipfile.ZipFile(Zipfile)
			ow = open(wordlist, "r").readlines()
			n_words = len(ow)
			print(Mrakp,"Total Passwords To Test:", n_words)
			starttime = time.time()
			pwdtries = 0 
			with open(wordlist, "rb") as wordlist:
			    for word in tqdm(wordlist, total=n_words, unit="word"):
			    	pwdtries+=1
			    	try:
			    		zip_file.extractall(pwd=word.strip())
			    	except:
			    		continue
			    	else:
			    		solved = True
			    		clear()
			    		with open('password.txt','w+') as passfile:
			    			passfile.write(word.decode().strip())
			    			passfile.close()
			    			print()
			    			closetime = time.time()
			    			print(Mrakp,"Password Found:", word.decode().strip())
			    			print()
			    			print (ast,"Starting Time ",starttime)
			    			print (ast,"Closing  Time ",closetime)
			    			print (ast,"Passwords Tried  ",pwdtries)
			    			print (ast,"Average Speed ",pwdtries/(closetime-starttime))
			    			print()
			    			break
			    		try:
		    				os.remove('bwordlist.txt')
		    			except:
		    				pass
		    			
			

			if solved==False:
				print()	
				print(Mrak,"Password Not Found, Try Other Wordlist")
				print (ast,"Starting Time ",starttime)
				print (ast,"Closing  Time ",closetime)
				print(ast,"Reached end of Words")
				print (ast,"Passwords Tried  ",pwdtries)
				print (ast,"Average Speed ",pwdtries/(closetime-starttime))
				print()
				try:
					os.remove('bwordlist.txt')
				except:
					pass
		



# Checking System
System = platform.platform().split("-")[0]
if System=='Windows':
	Mrak,Mrakp = "["+Fore.RED+'-'+Style.RESET_ALL+']' ,'['+Fore.CYAN+'+'+Style.RESET_ALL+']' 

elif System=='Linux':
	Mrak,Mrakp = "["+Fore.RED+'X'+Style.RESET_ALL+']' ,'['+Fore.GREEN+'✔'+Style.RESET_ALL+']' 

arow1,arow = "["+Fore.GREEN+'=>'+Style.RESET_ALL+']' ,Fore.GREEN+'->'+Style.RESET_ALL 
arow2 ,arow3 = "["+Fore.GREEN+'==>'+Style.RESET_ALL+']' ,"["+Fore.GREEN+'<='+Style.RESET_ALL+']'
revarow = "["+Fore.GREEN+'<=='+Style.RESET_ALL+']'
C,I,ast = Fore.RED+'010101'+Style.RESET_ALL,'['+Fore.RED+'!'+Style.RESET_ALL+"]",'['+Fore.CYAN+'*'+Style.RESET_ALL+']'

def Banner(SHELL=None):
	#global SHELL
	D = Fore.WHITE+'['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	CN = Fore.LIGHTCYAN_EX+' CodeName: '+Style.RESET_ALL+":"+Fore.RED+"N@RAMInA$SnFLiCKETBuTKS"+Style.RESET_ALL
	CB = Fore.LIGHTCYAN_EX+'        Created By'+Style.RESET_ALL+":"+Fore.RED+'  AKB'+Style.RESET_ALL
	VE = Fore.LIGHTCYAN_EX+'        Version'+Style.RESET_ALL+":"+Fore.RED+'  4.0.0'+Style.RESET_ALL


	BSY1 = Fore.LIGHTRED_EX+'Deeper:'+Style.RESET_ALL+Fore.LIGHTCYAN_EX+' Help'+Style.RESET_ALL
	BSY1+='\n\n'+Fore.YELLOW+'[!] HELP NOT AVAILABLE'+Style.RESET_ALL
	BSY1+='\n'+Fore.GREEN+".=======================."+Style.RESET_ALL
	BSY1+='\n'+Fore.GREEN+'|                       |'+Style.RESET_ALL
	BSY1+='\n'+Fore.GREEN+'|  '+Fore.LIGHTRED_EX+'SHALL DEEPER RC0X1 '+Fore.GREEN+'  |'+Style.RESET_ALL
	BSY1+='\n'+Fore.GREEN+'|                       |'+Style.RESET_ALL
	BSY1+='\n'+Fore.GREEN+'.=======================.'+Style.RESET_ALL
	BSY1+= '\n'+Fore.RED+'\_....-------------...._/ '+Style.RESET_ALL
	
	
	Bx = Fore.LIGHTRED_EX+"""
|\    /| |\    /| |\    /| |\  / |\    /| |~\       |    |~\       
| \  / | | \  / | | \  / | | \/  | \  / | |  \      |    |  \      
|  \/  | |  \/  | |  \/  | |     |  \/  | |  /   _  |    |  /   _  
|  /\  | |      | |      | |     |      | |_/   |_| |\   |_/   |_| 
| /  \ | |      | |      | | /\  |      | | \       | \  | \       
|/    \| |      | |      | |/  \ |      | |  \      |  \ |  \      ###DEEPER####                 
	"""+Style.RESET_ALL
	#Bx+='\n'+ Fore.CYAN+' Version'+Fore.RED+' 3.1.0 '+Style.RESET_ALL+':'+Fore.CYAN+' Code'+Fore.RED+' N@RAMInA$SnFLiCKETBuTKS  '+Style.RESET_ALL
	Bx+='\n'+Fore.RED+'\_............------------------------------............_/ '+Style.RESET_ALL



	B1 = """
o    o--o   O  o   o o--o     o   o o--o     o  o o--o o--o  o--o 
|    |     / \ |   | |        |\ /| |        |  | |    |   | |    
|    O-o  o---oo   o O-o      | O | O-o      O--O O-o  O-Oo  O-o  
|    |    |   | \ /  |        |   | |        |  | |    |  \  |    
O---oo--o o   o  o   o--o     o   o o--o     o  o o--o o   o o--o 
                                                           					 
{}  {}   {}                       
{}  {}              {}
{}  {}               {}
\_.------------------------------------------._/ 
""".format(D,CN,D,D,CB,D,D,VE,D,)
	

	TEXT = Fore.LIGHTCYAN_EX+'Leve Me Here'+Style.RESET_ALL
	DOT = Fore.RED+'. .  .  . .'+Style.RESET_ALL
	T = Fore.RED+'\_.------._/'+Style.RESET_ALL
	B2 = """
 L v  M  H r            
 X X  X  X X      
 X X  X  X X      
 X X  X  X X 
 X X  X  X X      
 X X  X  X X
 {}			

 {}
 {}

""".format(DOT,TEXT,T)
	Down_Ban = Fore.YELLOW+ 'Downloading Private Key From Secure Server Using Api_Sec_pr041 '+Style.RESET_ALL
	Down_Ban +='\n'+'Connecting To 198.265.124.6 ....'+Fore.RED+' Failed'+Style.RESET_ALL
	Down_Ban+='\n' 'Connecting To Sec_PR_01X4 Using Proxy 196.164.214.203'+'\n'+'You Are Connected To >> '+Fore.LIGHTYELLOW_EX+'Sec_PR_01X4'+Style.RESET_ALL
	Down_Ban+='\n'+Fore.LIGHTCYAN_EX+'Start Downloading Key ....'+Style.RESET_ALL
	Down_Ban += '\n'+'Progress'+Fore.GREEN+' %100'+Style.RESET_ALL+' Remaining 0 Seconds '
	Down_Ban+='\n'+Mrakp+' Private Key Save as /root/Save/Keys/PrivateKey.Pem'
	Down_Ban+='\n'+Mrakp+' Using /root/Save/Keys/PrivateKey.Pem To Decrypted Files....'
	Down_Ban+='\n'+Mrakp+Fore.LIGHTGREEN_EX+' ALL Files Decrypted Successfully'+Style.RESET_ALL
	Down_Ban+='\n'+'Removing PrivateKey.. '+'['+Fore.GREEN+'OK'+Style.RESET_ALL+']\n'
	Down_Ban+='\n'+ Fore.RED+'\_..........-------------------------------------.........._/ '+Style.RESET_ALL




	T1 = Fore.RED+'\_.------------------._/ '+Style.RESET_ALL
	T2 =  Fore.LIGHTCYAN_EX+'\_.---------------------------------._/'+Style.RESET_ALL
	B3W = Fore.LIGHTRED_EX+'DC:\>'+Fore.LIGHTCYAN_EX+' RSA.generate'+Style.RESET_ALL
	B3W1 = Fore.LIGHTRED_EX+'DC:\>'+Fore.LIGHTYELLOW_EX+' key.export'+Style.RESET_ALL
	B3W2 = Fore.LIGHTRED_EX+'DC:\> '+Fore.LIGHTGREEN_EX+'Run'+Style.RESET_ALL
	B3W3 = Fore.LIGHTRED_EX+'DC:\>'+Style.RESET_ALL+' D4199FB2A0E34'
	B3W4 = Fore.LIGHTRED_EX+'DC:\> '+Fore.YELLOW+'PrivateKey.Save'+Style.RESET_ALL
	B3WX = Fore.LIGHTRED_EX+'DC:\>'+Style.RESET_ALL+' -----RSA------'
	B3 = """
/+=====================+\ 
||{}   || 						
||{}     || 					
||{}            || 		 				
||{}  || 
||{}||
||{} ||
\+====================+/   
{}
""".format(B3W,B3W1,B3W2,B3W3,B3W4,B3WX,T1)

########### BANNER SHELS ###########
	if SHELL=='ENC':
		B4 = """
DC:\> Ｄ Ｅ Ｅ Ｐ Ｅ Ｒ ＄ Ｅ Ｎ Ｃ ＠ Ｓ Ｈ Ｅ Ｌ Ｌ >
{}
""".format(T2)
	else:
		B4 = ""

	if SHELL=="DEC":
		B5 = """
DC:\> Ｄ Ｅ Ｅ Ｐ Ｅ Ｒ ＄ Ｄ Ｅ Ｃ ＠ Ｓ Ｈ Ｅ Ｌ Ｌ >
{}
""".format(T2)
	else:
		B5 = ""


	if B4=="":
		Banners = [Fore.CYAN+B1+Style.RESET_ALL,Fore.CYAN+B2+Style.RESET_ALL,B3+Style.RESET_ALL,Fore.LIGHTRED_EX+B5+Style.RESET_ALL,BSY1,Down_Ban,Bx]
	
	if B5 =="":
		Banners = [Fore.CYAN+B1+Style.RESET_ALL,Fore.CYAN+B2+Style.RESET_ALL,B3+Style.RESET_ALL,Fore.LIGHTRED_EX+B4+Style.RESET_ALL,BSY1,Down_Ban,Bx]
		#Banners = [Fore.CYAN+B1+Style.RESET_ALL,Fore.CYAN+B2+Style.RESET_ALL,Fore.CYAN+B3+Style.RESET_ALL,Fore.LIGHTRED_EX+B4+Style.RESET_ALL,Fore.LIGHTRED_EX+B5+Style.RESET_ALL]


	#print(Down_Ban)
	print(random.choice(Banners))
	


#thread = threading.Thread(target=Sp_Dots,args=('try to Crack hash ','lcyan',), daemon=True).start()

def Genrate_Keys():
	clear()
	W = Fore.RED+'Key Generation'+Style.RESET_ALL
	print("""
 ------------------------------------------
|             {}	          |
 ------------------------------------------
	""".format(W))
		
	PrKey = "private.pem"
	PubKey = "public.pem"
	if os.path.exists(PubKey) and os.path.exists(PrKey) :
		print()
		print(Mrak+' Keys already exists')
		print(I,'Press Enter To [Returning]',end="");input()
		main()
		#CH = input('Do You Want To Overwrite public.pem [Y/N]: ')
		

	else:
		Counter = None
		CURSOR_UP_ONE = '\x1b[1A' 
		ERASE_LINE = '\x1b[2K' 
		print(ast,'This Process It Might Take 20 To 180 Seconds ')
		print()
		#thread = threading.Thread(target=Sp_Dots,args=('Generate RSA Key Length 3072 ','lcyan',), daemon=True).start()
		stop_threads = False
		t1 = threading.Thread(target = spinner_01, args =('Generate RSA Key Length 4096',lambda : stop_threads, )) 
		t1.start() 



		#s = time.process_time()	
		key = RSA.generate(4096)
		Counter = 1
		#e = time.process_time()	
		#print(s-e)
		stop_threads = True
		t1.join()

		print(Mrakp,'Key Generated Successfully')
		with Halo(text='Export Private Key', spinner='dots') as sp:
			sp.start()
			private_key = key.export_key()
			file_out = open("private.pem", "wb")
			file_out.write(private_key)
			file_out.close()
			sleep(2)
		
		print(Mrakp,'Export Private Key ['+Fore.GREEN+'Done'+Style.RESET_ALL+']')
		with Halo(text='Export Public Key', spinner='dots') as sp:
			sp.start()
			public_key = key.publickey().export_key()
			file_out = open("public.pem", "wb")
			file_out.write(public_key)
			file_out.close()
			sleep(2)
		
		print(Mrakp,'Export Public Key ['+Fore.GREEN+'Done'+Style.RESET_ALL+']')
		print(Mrakp,'Recommended Save Private Key To Usb Drive ')
		print('['+Fore.CYAN+'!'+Style.RESET_ALL+'] PRESS ENTER TO RETURN TO MENU (^.^): ',end="");input()
		




def get_size(start_path = None):
	total_size = 0
	for dirpath, dirnames, filenames in os.walk(start_path):
	    for f in filenames:
	        fp = os.path.join(dirpath, f)
	        total_size += os.path.getsize(fp)
	return total_size

def sizeof_fmt(num, suffix='B'):
	for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
		if abs(num) < 1024.0:
			return "%3.1f%s%s" % (num, unit, suffix)
		num /= 1024.0
	return "%.1f%s%s" % (num, 'Yi', suffix)




def encryption():
	clear()
	GCWD = os.getcwd()
	if os.path.exists("private.pem") and os.path.exists('public.pem'):
		pass


	else:
		clear()
		print("""
  **********************************************************
  **      	{} Error Keys Not Found                  **
  **               Genrate Keys Frist                     **
  **********************************************************
			""".format(I))
		#print(Mrak,'public.pem Not Found ')
		print(I+' PRESS ENTER TO [RETURN] ',end="");input()
		main()

	
	username = getpass.getuser()
	bufferSize = 64 * 1024
	Banner('ENC')
	print()
	print(ast,'Insert Path To Folder Or File Or Partition')

	print('┌─'+Style.RESET_ALL+'['+Fore.CYAN+':DeeperCrypto'+Style.RESET_ALL+'[──['+Fore.RED+'Encryption'+Style.RESET_ALL+']:',end="")
	Data_Path = input()
	if os.path.isdir(Data_Path):
		Data = 'Folder'
	

	elif os.path.isfile(Data_Path):
		Data = 'File'
		if Data_Path.split('.')[-1]=='aes':
			print(Mrak,'Error already Encrypted File [enc]')
			input(I+' PRESS Enter To [Return]')
			encryption()
		

	else:
		if Data_Path=="":
			encryption()
		else:
			print()
			print(Mrak,'Error Path Not [Exists] Press Enter To Continue [<=]')
			input()
			encryption()

	print()
	print(Fore.CYAN+'++++++++++++++++++++++++++++++++++++++'+Style.RESET_ALL)
	
	#try:


	print(ast,'Do You Want To Set Password Random [Y/N]')
	print('┌─'+Style.RESET_ALL+'['+Fore.CYAN+':DeeperCrypto'+Style.RESET_ALL+'[──['+Fore.RED+'Password'+Style.RESET_ALL+']:',end="")
	#print(ast,'Set Verbose [True|False]?',end="") ;
	choice_Pass_Meth = input().lower()

	#choice_Pass_Meth = input(':? ').lower()
	if choice_Pass_Meth =="y":
		length = 32
		specialCharacter = [random.choice(string.punctuation) for character in range(length)]
		wordLower = [random.choice(string.ascii_lowercase) for lower in range(length)]
		wordUpper = [random.choice(string.ascii_uppercase) for upper in range(length)]
		numbers = [random.choice(string.digits) for number in range(length)]
		generatedPassword = ''.join(specialCharacter + wordLower + wordUpper + numbers)
		generatedPassword = ''.join(random.choice(generatedPassword) for value in range(length))
		#generatedPassword += ''.join(chr(random.randint(0, 0xFF)) for i in range(16))

		AES_KEY = generatedPassword

	
		

	elif choice_Pass_Meth =='n':
		clear()
		print(Fore.RED+"+------------++-------------------------++-------------------+"+Style.RESET_ALL)
		print('| [!] The encryption key must be either',end="")
		print(Fore.MAGENTA+' 16, 24 or 32 '+Style.RESET_ALL+Fore.LIGHTCYAN_EX+' bytes '+Style.RESET_ALL+' |',end="") ;print()
		print('|   	    long Longer keys are more secure     	     | ')
		print('|        Password Like &OVy9F51j`|ja5{O                      |')
		print(Fore.RED+'+------------++-------------------------++-------------------+ '+Style.RESET_ALL)
		while True:
			print(ast,'Insert Password')
			print('┌─'+Style.RESET_ALL+'['+Fore.CYAN+':DeeperCrypto'+Style.RESET_ALL+'[──['+Fore.RED+Style.RESET_ALL+']:',end="")
			AES_KEY = getpass.getpass() 
			list_pass = set()
			specialCharacter = (string.punctuation)
			for i in AES_KEY:
			    if i.isupper():
			      list_pass.add('1')
			    elif i.islower():
			      list_pass.add('2')
			    elif i.isdigit():
			       list_pass.add('3')
			    elif i in specialCharacter:
			       list_pass.add('4')

			if len(AES_KEY) ==16 or len(AES_KEY) ==24 or len(AES_KEY) ==32:
			  list_pass.add('5')

			if len(list_pass) == 5:
				break

			
			else: 
			  print(Mrak,"Password invalid ")
			  print(I,'Password must has lowercase uppercase digits specialCharacter and length 16 or 24 or 32')
			  continue

			if AES_KEY=="" :
				print(Mrak,'Error Blank Password ')
				continue
			
		
	else:
		print(Mrak,'Error invalid Input ') ;print(I,'PRESS Enter To Return' , end="") ; input() ;encryption()


	
	#clear()
	if Data=='Folder':
		print()
		print(Fore.CYAN+'++++++++++++++++++++++++++++++++++++++'+Style.RESET_ALL)
		while True:
			print(ast,'Recommended False')
			print(ast,'Insert Verbose [True|False]')
			print('┌─'+Style.RESET_ALL+'['+Fore.CYAN+':DeeperCrypto'+Style.RESET_ALL+'[──['+Fore.RED+'Verbose'+Style.RESET_ALL+']:',end="")
			#print(ast,'Set Verbose [True|False]?',end="") ;
			verbose = input( ).lower()
			if verbose=='false' or verbose=='true':
				break
			else:
				continue
	else:
		verbose = True
		

	clear()
	if verbose=='true':

		print(ast,'Genrate Random Complix Password')
		stop_threads = False
		t1 = threading.Thread(target = progressBar1, args =(lambda : stop_threads, )) 
		t1.start() 
		sleep(3)
		stop_threads = True
		t1.join() 

		#print()
		for i in range(1,40):
			KEY = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(60))
			with yaspin(text=KEY) as sp:
			    time.sleep(0.040)
			    sp.hide()
			    sys.stdout.write('\r'+KEY)
			    sp.hide()
			    sp.show()
		ERASE_LINE = '\x1b[2K' 
		sys.stdout.write(ERASE_LINE) 
		print('\r')
		print(Mrakp,'Random Password Generated Successfully')
		sleep(2)
	else:
		sleep(1)
		
	print(Mrakp,'Startet Crypting')
	sleep(1)
	data = AES_KEY
	Passw = data
	data = data.encode("utf-8")
	if os.path.exists('encrypted_data.bin'):
		while True:

			print(I,'Warning Do You Want To Overwrite encrypted_data.bin This File Contains Encrypted Password [Y|N]: ',end="");x=input().lower()
			if x=='y':
				file_out = open("encrypted_data.bin", "wb")
				break


			elif x=='n':
				break
				sys.exit()

			else:
				print(Mrak,'Error Choice y or n !!!!')
				continue
	else:
		file_out = open("encrypted_data.bin", "wb")


	with Halo(text='Reading Key', spinner='dots') as sp:
		sp.start()
		sleep(2)
		sp.clear()

	
	
	#print(Mrakp,'Reading Key')
	recipient_key = RSA.import_key(open("public.pem").read())
	session_key = get_random_bytes(16)

	cipher_rsa = PKCS1_OAEP.new(recipient_key)
	enc_session_key = cipher_rsa.encrypt(session_key)

	cipher_aes = AES.new(session_key, AES.MODE_EAX)
	ciphertext, tag = cipher_aes.encrypt_and_digest(data)
	[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
	file_out.close()
	sleep(1)
	

	print(Mrakp,'Key imported')
	sleep(0.90)




	if Data=="Folder":
		print(Mrakp,'Setting Root Directory')
		sleep(2)
	
		print(Mrakp,'Root Directory set')
		print(Mrakp,'Processing Files')
		sleep(2)
	try:
		if Data=="Folder":
			#os.chdir(Data_Path)
			listFiles = os.listdir()

			
			path = Data_Path
			Directorys = []
			files = []
			for r, d, f in os.walk(path):
			    for file in f:
			    	#if file.split('.')[-1] in extensions:
			        files.append(os.path.join(r, file))
			    for Dir in d:
			    	Directorys.append(Dir)
			Directorys.insert(0,Data_Path.split('\\')[-1])
			def REMOVE_SPACE(list):
			  global NEW_LIST
			  NEW_LIST = []
			  for i in list:
			    i=i.replace(" ","")
			    NEW_LIST.append(i)

			
			CWD = os.getcwd()
			# Checks for spaces in dirs sub dirs files and rmove it 
			################################################################
			
			#global FILES_NE , Return_Code ,DIRS_NE
			parent = Data_Path
			FILES_NE = []
			DIRS_NE = []
			for path, folders, files in os.walk(parent):
				for f in files:
					os.chdir(path)
					old = os.path.join(path, f)
					bad_chars = [r' ', r',', r'-', r'&', r'[', r']', r'(', r')', r'__',r'  ',r'   ',r'    ',r'     ',r';',r'@',r'$']
					for bad_char in bad_chars:
						if bad_char in f:
							new = old.replace(bad_char,"")
							new = new.split('\\')[-1]
							FILES_NE.append(new)
							if verbose=='true':
								print(ast,"==>",old+' Replace To',new)
								sleep(0.001)
							else:
								pass
							
							#print("==>",new)
							#print(os.getcwd())
							#input()
							try: 
								os.rename(old, new)
								Return_Code = 0
							except FileNotFoundError:
								Return_Code = 0
								pass
							except PermissionError:
								pass
							except FileExistsError:
								pass
							os.chdir('..')

				for i in range(len(folders)):
					new_name = folders[i].replace(' ', '_')
					bad_chars = [r' ', r',', r'-', r'&', r'[', r']', r'(', r')', r'__',r'  ',r'   ',r'    ',r'     ',r';',r'@',r'$']
					for bad_char in bad_chars:
						if bad_char in new_name:
							new_name = new_name.replace(bad_char,'')
							DIRS_NE.append(new_name)
							if verbose=='true':
								print(ast,folders[i], "==> ", new_name)
								sleep(0.001)
							else:
								pass
							#input()
						old = os.path.join(path, folders[i])
						new = os.path.join(path, new_name)
						try:
							os.rename(old, new)
							folders[i] = new_name
							RET_COD = 0
						except FileNotFoundError:
							pass 
							RET_COD = 1  
						except PermissionError:
								pass
						except FileExistsError:
								pass

			
			try:
				if Return_Code == 0:
					path = Data_Path
					Directorys = []
					files = []
					for r, d, f in os.walk(path):
					    for file in f:
					    	pass
					        #files.append(os.path.join(r, file))
					    for Dir in d:
					    	Directorys.append(Dir)
					if System=='Linux':
						Directorys.insert(0,Data_Path.split('/')[-1])
					else:

						Directorys.insert(0,Data_Path.split('\\')[-1])


					

			except UnboundLocalError:
				pass

			

			os.chdir(CWD)
		
			temp_folder = 'temp'
			if os.path.exists(temp_folder):
				pass
			else:
				os.mkdir(temp_folder)
			file = 'temp.txt'
			temp_file = os.path.join(temp_folder,file)

			for path, folders, FILES in os.walk(parent):
				for f in FILES:
					#FILE_PATH = os.path.join(path,f)
					if System=='Windows':
							filepath = path+'\\'+f
					else:
						filepath = path+'/'+f

					with open(temp_file, 'a+', encoding='utf-8') as file:
						file.write(filepath+'\n')
					file.close()


				


			open_temp_file = open(temp_file,'r',encoding='utf-8')

			FINAL_FILES = open_temp_file.readlines()	
			open_temp_file.close()



			if len(FINAL_FILES)==0:
				print(Mrak,'Error Empty Folder')
				sys.exit()
			AES_FILES = []
			for path, folders, FILES in os.walk(parent):
				for f in FILES:
					if '.aes' in f:
						AES_FILES.append(f)
					
			
			

			if len(AES_FILES)== len(FINAL_FILES):
				print(Mrak,'Faild Encryption All Fill Encrypted')
				sys.exit()
			
			
			if len(AES_FILES)!=0:
				print(I,'Found {} Already Encrypting Files'.format(len(AES_FILES)))


			with Halo(text='Counting Files', spinner='dots') as sp:
				sp.start()
				sleep(3)
			if AES_FILES!=0:
				LEN_FILES = len(FINAL_FILES) ; COV_LEN_Files = int(LEN_FILES)
				LEN_AES_FILES = len(AES_FILES) ;COV_LEN_AES_F = int(LEN_AES_FILES)
				FINAL_FILES_COUNT = COV_LEN_Files - LEN_AES_FILES
				print(Mrakp,'{} Files Will Encrypted'.format(FINAL_FILES_COUNT))
			else:
				Count_Files = len(FINAL_FILES) ; print(Mrakp,'{} Files Will Encrypted'.format(Count_Files))
			print(Mrakp,'Folders {}'.format(len(Directorys)))
			with Halo(text='Geting Files Size', spinner='dots') as sp:
				sp.start()
				GetDataSize = sizeof_fmt(get_size(Data_Path))
			print(Mrakp,'Files Size {}'.format(GetDataSize))
			sleep(2)
			
			if not Directorys:
				if System=='Linux':
					Directorys = Data_Path.replace(Data_Path.split('/')[-1],'')

				else:
					Directorys = Data_Path.replace(Data_Path.split('\\')[-1],'')
					
					



			if len(Directorys)<=150:
				if len(Directorys)!=0:
					print(Mrakp,'Folders:');print(Directorys)
			
			sleep(2)
			clear()
			

			start = time.time()
			CURNT_DIR = os.getcwd()


			# FAST ENCRYPTION
			if verbose=='false':
				for f in tqdm(FINAL_FILES, total=len(FINAL_FILES), unit="File"):
					i=f.strip('\n')
					ENC_CODE = 1
					if System=="Windows":
						Path = i.replace(i.split('\\')[-1],'')
						File_Name = i.split('\\')[-1]
					elif System=='Linux':
						Path = i.replace(i.split('/')[-1],'')
						File_Name = i.split('/')[-1]

					outputfile=i+".aes"
					chunksize = 64*1024
					try:
						filesize = str(os.path.getsize(i)).zfill(16)
					except FileNotFoundError:
						pass
					IV = Random.new().read(16)
					try:
						encryptor = AES.new(AES_KEY.encode('utf-8'), AES.MODE_CBC, IV)
					except Exception as E:
						print(Mrak,E)
						print(Mrakp,'Recommended Choice Random Password' )
						sys.exit()
					if '.aes' not in i:
						with open(i, 'rb') as infile:
							with open(outputfile, 'wb') as outfile:
								outfile.write(filesize.encode('utf-8'))
								outfile.write(IV)
								while True:
									chunk = infile.read(chunksize)

									if len(chunk) == 0:
										break
									elif len(chunk)%16 != 0:
										chunk += b' '*(16-(len(chunk)%16))

									outfile.write(encryptor.encrypt(chunk))
									ENC_CODE = 0
					else:
						pass
			else:
				for i in FINAL_FILES:
					i=i.strip('\n')
							
					ENC_CODE = 1
					if System=="Windows":
						Path = i.replace(i.split('\\')[-1],'')
						File_Name = i.split('\\')[-1]
					elif System=='Linux':
						Path = i.replace(i.split('/')[-1],'')
						File_Name = i.split('/')[-1]

					outputfile=i+".aes"
					chunksize = 64*1024
					try:
						filesize = str(os.path.getsize(i)).zfill(16)
					except FileNotFoundError:
						pass
					IV = Random.new().read(16)
					try:
						encryptor = AES.new(AES_KEY.encode('utf-8'), AES.MODE_CBC, IV)
					except Exception as E:
						print(Mrak,E)
						print(Mrakp,'Recommended Choice Random Password' )
						sys.exit()
					if '.aes' not in i:
						with open(i, 'rb') as infile:
							with open(outputfile, 'wb') as outfile:
								outfile.write(filesize.encode('utf-8'))
								outfile.write(IV)
								while True:
									chunk = infile.read(chunksize)

									if len(chunk) == 0:
										break
									elif len(chunk)%16 != 0:
										chunk += b' '*(16-(len(chunk)%16))

									outfile.write(encryptor.encrypt(chunk))
									ENC_CODE = 0
								
								
								
								print(Mrakp,"Encrypting  {} ".format(File_Name))
								
		    
						
						
						
					
					else:
						pass
						print(Mrak,"Faild Already Encrypting File {}".format(File_Name))

				
					if len(AES_FILES)>=100:
						print(Mrak,"Encrypting Faild !!!!!")
						sys.exit()
					
					
			
			stop_threads = False
			t1 = threading.Thread(target = SPAN_EQ, args =('Processing Encrypting Files',lambda : stop_threads, )) 
			t1.start() 

			if verbose=='false':
				for i in FINAL_FILES:
					i=i.strip('\n')
					encfile =i+".aes"
					if os.path.exists(encfile):
						os.remove(i)
			else:
				for i in FINAL_FILES:
					i=i.strip('\n')
					if os.path.exists(i):
						os.remove(i)


			stop_threads = True
			t1.join()
			
			Clean_Gen_Files()
			if  ENC_CODE ==0:
				
				#clear()
				#print('\n')
				#print(Mrakp,'Encryption [Done]')
				end = time.time()
				hours, rem = divmod(end-start, 3600)
				minutes, seconds = divmod(rem, 60)
				print()
				print (ast,"Starting Time ",start)
				print (ast,"Closing  Time ",end)
				Count_Files = len(FINAL_FILES)
				print (ast,"Encrypted Files",Count_Files)
				print (ast,"Average Speed ",Count_Files/(end-start))
				print(ast+' Elapsed Time '+"{:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
				print()
				print(I,'Recommended To Move encrypted_data.bin To Usb Or Saveplace ')
				print(I,'encrypted_data.bin and privatekey.pem Uses For Decryption')
				print(I,'Without encrypted_data.bin decryption Files Will Corrupted ')

				
				print()
				print('['+Fore.CYAN+'!'+Style.RESET_ALL+'] PRESS ENTER TO CONTINUE (^.^): ',end="");input()
				#clear()
				sys.exit()
			else:
				print('['+Fore.CYAN+'!'+Style.RESET_ALL+'] PRESS ENTER TO CONTINUE (^.^): ',end="");input()
				#clear()
				sys.exit()

			

		elif Data=="File":
			File = Data_Path
			outputfile=Data_Path+".aes"
			if Data_Path.count('aes')==0:
				chunksize = 64*1024
				filesize = str(os.path.getsize(File)).zfill(16)
				IV = Random.new().read(16)
				encryptor = AES.new(AES_KEY.encode('utf-8'), AES.MODE_CBC, IV)

				with open(File, 'rb') as infile:
					with open(outputfile, 'wb') as outfile:
						outfile.write(filesize.encode('utf-8'))
						outfile.write(IV)

						while True:
							chunk = infile.read(chunksize)

							if len(chunk) == 0:
								break
							elif len(chunk)%16 != 0:
								chunk += b' '*(16-(len(chunk)%16))

							outfile.write(encryptor.encrypt(chunk))

	
				print(Mrakp,"Encrypting {} ".format(Data_Path))
				Enc_File = outputfile
				if os.path.exists(Enc_File):
					if System=="Windows":
						cmd('del {}'.format(Data_Path))
					elif System=="Linux":
						if os.path.exists(Enc_File):
							cmd('rm {}'.format(Data_Path))

		print(Style.RESET_ALL)
		os.chdir(GCWD)
		print('['+Fore.CYAN+'!'+Style.RESET_ALL+'] PRESS ENTER TO CONTINUE (^.^): ',end="");input()
		clear()
		sys.exit()
		#main()

	except KeyboardInterrupt:
		print()
		print("[+] Detecting [CTRL+C] Quiting.... ", end="")
		sleep(1)
		clear()
		os.chdir(GCWD)
		Clean_Gen_Files()
		sys.exit()




def Decryption():
	if os.path.exists('encrypted_data.bin') and os.path.exists('public.pem'):
		pass

	else:
		clear()
		print(Mrak,'Error encrypted_data.bin & public.pem Not Found')
		print()
		print('['+Fore.CYAN+'!'+Style.RESET_ALL+'] PRESS ENTER TO CONTINUE (^.^): ',end="");input()
		sys.exit()
	
	GCWD = os.getcwd()
	os.chdir(GCWD)
	clear()
	username = getpass.getuser()
	bufferSize = 64 * 1024
	Banner('DEC')
	print()
	print(Fore.CYAN+'++++++++++++++++++++++++++++++++++++++'+Style.RESET_ALL);print()
	print(ast,'Insert Path To Folder Or File Or Partition')
	print('┌─'+Style.RESET_ALL+'['+Fore.CYAN+':DeeperCrypto'+Style.RESET_ALL+'[──['+Fore.RED+'Decryption'+Style.RESET_ALL+']:',end="")
	Data_Path = input()
	if os.path.isdir(Data_Path)==True:
		Data = 'Folder'

	elif os.path.isfile(Data_Path)==True:
		Data = 'File'

	else:
		print(Mrak,'Error Path Not [exists] Press Enter To Continue {}'.format(arow3))
		input()
		Decryption()
	
	if Data=='Folder':
		print()
		while True:
			print(Fore.CYAN+'++++++++++++++++++++++++++++++++++++++'+Style.RESET_ALL);print()
			print(ast,'Recommended False')
			print(ast,'Insert Verbose [True|False]')
			print('┌─'+Style.RESET_ALL+'['+Fore.CYAN+':DeeperCrypto'+Style.RESET_ALL+'[──['+Fore.RED+'Verbose'+Style.RESET_ALL+']:',end="")
			#print(ast,'Set Verbose [True|False]?',end="") ;
			verbose = input( ).lower()
			if verbose=='false' or verbose=='true':
				break
			else:
				continue

	
	else:
		verbose = True
		

	
	print()
	print(Fore.CYAN+'++++++++++++++++++++++++++++++++++++++'+Style.RESET_ALL)
	try:
		#file_in = open("encrypted_data.bin", "rb")
		print()
		print(ast,'Insert Path To encrypted_data.bin ')
		print('┌─'+Style.RESET_ALL+'['+Fore.CYAN+':DeeperCrypto'+Style.RESET_ALL+'[──['+Fore.RED+'encrypted_data.bin'+Style.RESET_ALL+']:',end="")
		data_bin  = input( )

		if os.path.exists(data_bin):
			if data_bin.split('.')[-1]=='bin':
				file_in = open(data_bin, "rb")
			else:
				print(Mrak,'invalid encrypted_data.bin')
				sys.exit()
		else:
			print(Mrak,'Error Path Not [exists] Press Enter To Continue {}'.format(arow3))
			sys.exit()

		print()
		print(Fore.CYAN+'++++++++++++++++++++++++++++++++++++++'+Style.RESET_ALL)
		print()
		print(ast,'Insert Private Key Path')
		print('┌─'+Style.RESET_ALL+'['+Fore.CYAN+':DeeperCrypto'+Style.RESET_ALL+'[──['+Fore.RED+'ImportKey'+Style.RESET_ALL+']:',end="")
			
		Get_private_key= input()
		
		if Get_private_key.split('.')[-1]=="pem":
			pass

		else:
			print(Mrak,'Error invalid Private Key')
			sys.exit()

		clear()
		print(Mrakp,'Reading Key')
		private_key = RSA.import_key(open(Get_private_key).read())
		enc_session_key, nonce, tag, ciphertext = \
		   [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
		sleep(0.55)
		# Decrypt the session key with the private RSA key
		cipher_rsa = PKCS1_OAEP.new(private_key)
		session_key = cipher_rsa.decrypt(enc_session_key)
		print(Mrakp,'Key imported')
		sleep(1)
		print(Mrakp,'Start Decryption AES session key')
		sleep(2)
		# Decrypt the data with the AES session key
		cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
		data = cipher_aes.decrypt_and_verify(ciphertext, tag)
		Passw = data.decode("utf-8")
		print(Mrakp,'Decryption key [OK]')
		sleep(1)

	except ValueError:
		print(Mrak,'Incorrect Decryption invalid PrivateKey')
		sys.exit()


	
	if Data=="Folder":
		print(Mrakp,'Setting Root Directory')
		sleep(0.70)			
		print(Mrakp,'Root Directory set')
		sleep(1)
		print(Mrakp,'Processing Files')

	try:

		

		if Data=='Folder':
			temp_folder = 'temp'
			if os.path.exists(temp_folder):
				pass
			else:
				os.mkdir(temp_folder)


			

			file = 'temp1.txt'
			file1 = 'temp2.txt'
			temp_file = os.path.join(temp_folder,file)
			temp_F = os.path.join(temp_folder,file1)
			#os.chdir(Data_Path)
			listFiles = os.listdir()
			path = Data_Path
			Directorys = []
			files = []
			#if file.split('.')[-1]=='aes':
			for r, d, f in os.walk(path):
			    for file in f:
			    	#filepath = os.path.join(r,file)
			    	if System=='Windows':
			    		filepath = r+'\\'+file
			    	else:
			    		filepath = r+'/'+file

			    	with open(temp_file, 'a+', encoding='utf-8') as File:
			    		File.write(filepath+'\n')

			if System=='Linux':
				Wr = Data_Path.split('/')[-1]
			else:
				Wr = Data_Path.split('\\')[-1]
			Dir1 = Wr
			with open(temp_F, 'a+', encoding='utf-8') as r:
				r.write(Dir1+'\n')
			for r, d, f in os.walk(path):
			    for DIR in d:
			    	with open(temp_F, 'a+', encoding='utf-8') as r:
			    		r.write(DIR+'\n')

				
			 
			
			open_tempf=open(temp_F,'r',encoding='utf-8')

			open_temp_file = open(temp_file,'r',encoding='utf-8')

			files = open_temp_file.readlines()	
			Directorys = open_tempf.read().splitlines()
			open_tempf.close()
			open_temp_file.close()

			

			for f in files:
				f=f.strip('\n')
				if not 'aes' in f:
					AES_FILE =False

			AES_FILE = True
			if  AES_FILE!=False:
				sleep(0.55)
				Count_Files = len(files) ; print(Mrakp,'{} Files Will Decrypting'.format(Count_Files))
				#Directorys.insert(0,Data_Path.split('\\')[-1])
				print(Mrakp,'Folders {}'.format(len(Directorys)))
				with Halo(text='Geting Files Size', spinner='dots') as sp:
					sp.start()
					GetDataSize = sizeof_fmt(get_size(Data_Path))
				print(Mrakp,'Files Size {}'.format(GetDataSize))
				sleep(2)
				
				sleep(0.40)
				if not Directorys:
					Directorys = Data_Path
				if len(Directorys)<=150:
					print(Mrakp,'Starting Decrypting In Folders:');print(Directorys)
			
			

		
			else:
				print(ast,'Checking Encryption Files')
				sleep(3)
				print(I,'ERROR NOT ENCRYPTION FILES')

			# key , files

			sleep(2)
			clear()
			

			if  AES_FILE!=False:
				start = time.time()
			
			if verbose=='false':
				for i in tqdm(files, total=len(files), unit="File"):
					i=i.strip('\n')
					if System=='Linux':
						File_Name = i.split('/')[-1]
						Path = i.replace(i.split('/')[-1],'')

					else:
						File_Name = i.split('\\')[-1]
						Path = i.replace(i.split('\\')[-1],'')

					
					if i.count('aes')==1:
						#GetFileNameEx = outputfile[0]+"."+outputfile[-2]
						try:
							key = Passw
							chunksize = 64*1024
							outputFile = i.split('.aes')[0]
							

							with open(i, 'rb') as infile:
								filesize = int(infile.read(16))
								IV = infile.read(16)

								decryptor= AES.new(key.encode('utf-8'), AES.MODE_CBC, IV)

								with open(outputFile, 'wb') as outfile:
									while True:
										chunk = infile.read(chunksize)

										if len(chunk) == 0:
											break

										outfile.write(decryptor.decrypt(chunk))

									outfile.truncate(filesize)

					
							Return_Code = 200
						except ValueError:
							pass
							Return_Code = 404
							
			
					else:
						pass
						


			else:
				for i in files:
					i=i.strip('\n')
					if System=='Linux':
						File_Name = i.split('/')[-1]
						Path = i.replace(i.split('/')[-1],'')

					else:
						File_Name = i.split('\\')[-1]
						Path = i.replace(i.split('\\')[-1],'')

					outputfile=i.split('.')
					
					if i.count('aes')==1:
						GetFileNameEx = outputfile[0]+"."+outputfile[-2]
						try:
							key = Passw
							chunksize = 64*1024
							outputFile = i.strip('.aes')

							with open(i, 'rb') as infile:
								filesize = int(infile.read(16))
								IV = infile.read(16)

								decryptor= AES.new(key.encode('utf-8'), AES.MODE_CBC, IV)

								with open(outputFile, 'wb') as outfile:
									while True:
										chunk = infile.read(chunksize)

										if len(chunk) == 0:
											break

										outfile.write(decryptor.decrypt(chunk))

									outfile.truncate(filesize)

					
							Return_Code = 200
						except ValueError:
							Return_Code = 404
							pass
							print(Mrak+' Faild To Decrypting File  {} '.format(File_Name))
						else:
							print(Mrakp,"Decrypting  {} ".format(File_Name))

					else:
						print(Mrak+' Error Decryption {} Not Encrypted File   '.format(File_Name))
						

					


		elif Data=="File":
			File = Data_Path
			if Data_Path.count('aes')==1:
				try:
					key = Passw
					chunksize = 64*1024
					outputFile = File.split('.aes')[0]

					with open(File, 'rb') as infile:
						filesize = int(infile.read(16))
						IV = infile.read(16)

						decryptor= AES.new(key.encode('utf-8'), AES.MODE_CBC, IV)

						with open(outputFile, 'wb') as outfile:
							while True:
								chunk = infile.read(chunksize)

								if len(chunk) == 0:
									break

								outfile.write(decryptor.decrypt(chunk))

							outfile.truncate(filesize)
							Return_Code = 200


					
				except ValueError:
					Return_Code = 404
					pass

				if Return_Code ==200:
					print(Mrakp,"Decrypting {} ".format(Data_Path))
					dec_File = Data_Path.split('.aes')[0]
					if os.path.exists(Data_Path):
						if System=="Windows":
							cmd('del {}'.format(Data_Path))
						elif System=="Linux":
							cmd('rm {}'.format(Data_Path))
		
			else:
				pass

		
		try:
			if  AES_FILE!=False:
				stop_threads = False
				t1 = threading.Thread(target = SPAN_EQ, args =('Processing Decrypted Files',lambda : stop_threads, )) 
				t1.start() 

				if verbose=='false':
					for i in files:
						i=i.strip('\n')
						decfile = i.split('.aes')[0]
					
						if os.path.exists(decfile):
							os.remove(i)
				else:
					for i in files:
						i=i.strip('\n')
						decfile = i.split('.aes')[0]
						if os.path.exists(decfile):
							os.remove(i)


				stop_threads = True
				t1.join()
				Clean_Gen_Files
				end = time.time()
				hours, rem = divmod(end-start, 3600)
				minutes, seconds = divmod(rem, 60)
				print()
				print (ast,"Starting Time ",start)
				print (ast,"Closing  Time ",end)
				Count_Files = len(files)
				print (ast,"Decrypted Files",Count_Files)
				print (ast,"Average Speed ",Count_Files/(end-start))
				print(ast+' Elapsed Time '+"{:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
				print()
				print('['+Fore.CYAN+'!'+Style.RESET_ALL+'] PRESS ENTER TO CONTINUE (^.^): ',end="");input()
				clear()
				sys.exit()
			else:
				print('['+Fore.CYAN+'!'+Style.RESET_ALL+'] PRESS ENTER TO CONTINUE (^.^): ',end="");input()
				clear()
				sys.exit()
		except UnboundLocalError:
			pass
			print('['+Fore.CYAN+'!'+Style.RESET_ALL+'] PRESS ENTER TO CONTINUE (^.^): ',end="");input()
			clear()
			sys.exit()
		

	except KeyboardInterrupt:
		print()
		print("[+] Detecting [CTRL+C] Quiting.... ", end="")
		sleep(1)
		clear()
		try:
			os.remove(temp_file)
			os.remove(temp_F)
		except FileNotFoundError:
			pass
		sys.exit()

	

def SHELL_MODE_STYLE(): 
	S = Fore.LIGHTRED_EX+'SHELL\>'+Style.RESET_ALL
	CM = Fore.LIGHTCYAN_EX+r'DS:\> Ｄ Ｅ Ｅ Ｐ Ｅ Ｒ ＠ $ Ｈ Ｅ Ｌ Ｌ >'+Style.RESET_ALL
	CM+='\n'+ """
/+=====================+\ 
||                     || 
||                     || 
||     	 {}       || 
||                     || 
||                     ||
||                     ||
\+=====================+/   
	""".format(S)+Style.RESET_ALL



	


	Ast = Fore.LIGHTRED_EX+'''
    		.....
           .d$$$$*$$$$$$bc
        .d$P"    d$$    "*$$.
       d$"      4$"$$      "$$.
     4$P        $F ^$F       "$c
    z$%        d$   3$        ^$L
   4$$$$$$$$$$$$$$$$$$$$$$$$$$$$$F
   $$$F"""""""$F""""""$F"""""C$$*$
  .$%"$$e    d$       3$   z$$"  $F
  4$    *$$.4$"        $$d$P"    $$
  4$      ^*$$.       .d$F       $$
  4$       d$"$$c   z$$"3$       $F
   $L     4$"  ^*$$$P"   $$     4$"
   3$     $F   .d$P$$e   ^$F    $P
    $$   d$  .$$"    "$$c 3$   d$
     *$.4$"z$$"        ^*$$$$ $$
      "$$$$P"             "$$$P
        *$b.             .d$P"
          "$$$ec.....ze$$$"
              "**$$$**""
'''+Style.RESET_ALL

	Bmn = Fore.RED+"""
      aa@@@@@@@@@@@@@aa
   a@@@@@@@@@@@@@@@@@@@@@a
 a@@@@@@@@@@@@@@@@@@@@@@@@@a
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@~~~~@@@@@@@@@~~~~@@@@@@@
@@@@@@      @@@@@@@      @@@@@@
@@@@@@@aaaa@@@@@@@@@aaaa@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
`@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
@@@@@@@@~@@@~@@@~@@@~@@@@@@@@
 @@@@@@@@@@@@@@@@@@@@@@@@@@@
  @@@@@@@@~@@@~@@@~@@@@@@@@
   @@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@~@@@~@@@@@@@@
     `@@@@@@@@@@@@@@@@@'
         ~~@@@@@@@~~
"""+Style.RESET_ALL

	Bcrh = 'DATANET PROC RECORD: '+Fore.YELLOW+' 45-3456-W-3452'+Style.RESET_ALL+ Fore.RED+' Transet on/xc-3'+Style.RESET_ALL
	Bcrh+='\n'+'      FEDERAL RESERVE TRANSFER NODE'+'\n'+'           National Headquarters'
	Bcrh+='\n'+Fore.BLUE+'************ '+Style.RESET_ALL+ 'Cracker Input Station'+Fore.BLUE+ ' ************'+Style.RESET_ALL
	Bcrh+='\n'+'================================================================'
	Bcrh+='\n'+'['+Fore.GREEN+'1'+Style.RESET_ALL+']'+' Crack ssh (Code Prog:'+Fore.YELLOW+ '485-GWU'+Style.RESET_ALL+')'+Fore.RED+'   Transet T1/xc-4  D2-X0-4R'+Style.RESET_ALL
	Bcrh+='\n'+'['+Fore.GREEN+'2'+Style.RESET_ALL+']'+' Crack Telnet (Code Lin:'+Fore.YELLOW+ 'XRP-262'+Style.RESET_ALL+')'+Fore.RED+' Transet T2/xc-5  GP-84-FD'+Style.RESET_ALL
	Bcrh+='\n'+'['+Fore.GREEN+'3'+Style.RESET_ALL+']'+' Crack Password (Code :'+Fore.YELLOW+ '2LZP-517'+Style.RESET_ALL+')'+Fore.RED+' Transet T3/xc-6  YT-0X-Q8'+Style.RESET_ALL
	Bcrh+='\n'+'['+Fore.GREEN+'4'+Style.RESET_ALL+']'+' Bruteforce (Code :'+Fore.YELLOW+ '47-B34'+Style.RESET_ALL+')'+Fore.RED+'       Transet T4/xc-7  FF-FF-FF'+Style.RESET_ALL
	Bcrh+='\n'+'['+Fore.GREEN+'5'+Style.RESET_ALL+']'+' Crack Wpa2 (Code :'+Fore.YELLOW+ '20-5B43'+Style.RESET_ALL+')'+Fore.RED+'      Transet T5/xc-8  0X-TP-C1'+Style.RESET_ALL
	Bcrh+='\n'+'['+Fore.GREEN+'6'+Style.RESET_ALL+']'+' Crack Hard disk (Code :'+Fore.YELLOW+ '95-B6-01'+Style.RESET_ALL+')'+Fore.RED+'Transet T6/xc-9  CF-85-00'+Style.RESET_ALL
	Bcrh+='\n'+' ================================================================ '
	Bcrh+='\n'+Fore.GREEN+'		[ ]'+Style.RESET_ALL+' Select Option or ESC to Abort'

	HS_W = Fore.LIGHTRED_EX +Back.BLUE+' C R A C K E R H A S H E R '+Style.RESET_ALL
	HS = Fore.LIGHTYELLOW_EX+'%%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%'+Style.RESET_ALL
	HS+='\n'+Fore.LIGHTRED_EX+'%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'+Style.RESET_ALL
	HS+='\n'+'%%%%%%%     %%%%%%%%%     %%%%%%%%%%     %%%%%%%%%%%%%%%'+Style.RESET_ALL
	HS+='\n'+'%%%%%%%%%%'+ HS_W  +'%%%%%%%%%%%%%%%%%%%'
	HS+='\n'+'%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'+Style.RESET_ALL
	HS+='\n'+'%%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%'+Style.RESET_ALL
	HS+='\n'+'%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'+Style.RESET_ALL
	HS+='\n'+Fore.LIGHTGREEN_EX+'%%%%%%%     %%%%%%%%%     %%%%%%%%%%     %%%%%%%%%%%%%%%'+Style.RESET_ALL
	HS+='\n'+Fore.LIGHTMAGENTA_EX+'%%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%'+Style.RESET_ALL


	ac = Fore.LIGHTCYAN_EX+'___________________________________________________________'+Style.RESET_ALL
	ac +='\n'+'Try To Access Passwords'+Fore.LIGHTGREEN_EX+' -> '+Style.RESET_ALL+ Fore.YELLOW+'0XFFFF1RZX'+Style.RESET_ALL+' ['+Fore.RED+'Faild'+Style.RESET_ALL+']'
	ac+='\n'+ 'Using Method Cracker :ST164 To Accessing Passwords'+Fore.LIGHTRED_EX+'.....'+Style.RESET_ALL
	ac+='\n'+'Error:'+Fore.RED+' ffffffffff'+Style.RESET_ALL+' Error:'+Fore.YELLOW+' 0X4TTY10X '+Style.RESET_ALL+Fore.LIGHTYELLOW_EX+' 0x42cf8' +Style.RESET_ALL
	ac+='\n'+'<A>NEV/HJS<KBA> FUNCTIONS Not Working 0xx0xx '+Fore.RED+'Faild '+Style.RESET_ALL+' Try... '
	ac+='\n'+Fore.RED+'Faild:'+Style.RESET_ALL+Fore.YELLOW+' 0x0x0x0x0x0    :0322x1x01'+Style.RESET_ALL
	ac+='\n'+'Force Using Method CR0XDEB .... '+'['+Fore.LIGHTGREEN_EX+'CR0XDEB: Running'+Style.RESET_ALL+']'
	ac+='\n'+'Try '+Fore.LIGHTMAGENTA_EX+'............................'+Style.RESET_ALL
	ac+='\n'+'['+Fore.GREEN+'+'+Style.RESET_ALL+']'+Fore.GREEN+' Found'+Style.RESET_ALL+' 1 Hash Salt: Sha512'
	ac+='\n'+'Try To Crack Hash'+Fore.RED+' ..........................'+Style.RESET_ALL
	ac+='\n'+'['+Fore.GREEN+'+'+Style.RESET_ALL+']'+' Hash Cracked! '+Fore.RED+'*******'+Style.RESET_ALL

	sys_sock =Fore.LIGHTMAGENTA_EX+ """                                                                                                                                                                                                                                                                                                                                                                                                           
   	                                      .""--..__
                     _                     []       ``-.._                   
                  .'` `'.                  ||__           `-._               
                 /    ,-.\                 ||_ ```---..__     `-.            
                /    /:::\\               /|//}          ``--._  `.           
                |    |:::||              |////}                `-. \         
                |    |:::||             //'///                    `.\        
                |    |:::||            //  ||'                      `|       
                /    |:::|/        _,-//\  ||                             
               /`    |:::|`-,__,-'`  |/  \ ||                                
             /`  |   |'' ||           \   |||    H A S H E R :C R A C K E R                  
           /`    \   |   ||            |  /||                                
         |`       |  |   |)            \ | ||                       
        |          \ |   /      ,.__    \| ||                               
        /           `         /`    `\   | ||
       |                     /        \  / ||                                
       |                     |        | /  ||
       /         /           |        `(   ||                               
      /          .           /             ||
     |            \          |             ||                                
    /             |          /             ||               
   |\            /          |              ||                               
   \/`-._       |           /              ||                                                         
"""
	


	Banners = [CM,Bmn,sys_sock,Ast,Bcrh,HS]
	print(random.choice(Banners))
	







def Banners_Style():
		

	#################################################### Style
	D = Fore.WHITE+'['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	CN = Fore.LIGHTCYAN_EX+'        CodeName: '+Style.RESET_ALL+":"+Fore.LIGHTRED_EX +"HACkCrX"+Style.RESET_ALL
	CB = Fore.LIGHTCYAN_EX+'        Created By'+Style.RESET_ALL+":"+Fore.LIGHTRED_EX+'  AhmedBalaha'+Style.RESET_ALL
	VE = Fore.LIGHTCYAN_EX+'        Version'+Style.RESET_ALL+":"+Fore.LIGHTRED_EX+'  4.0.0'+Style.RESET_ALL


	b1t = Fore.LIGHTRED_EX+'DC:\> DEEPERCR'+Style.RESET_ALL
	B1 = """
	   /+===============+\ 
	   || {}|| 
	   ||               || 
	   ||               || 
	   ||               || 
	   ||               ||
	   \+===============+/   
{}  {}            {}                       
{}  {}      {}
{}  {}               {}
\_.------------------------------------------._/ 
		""".format(b1t,D,CN,D,D,CB,D,D,VE,D)


	B2 = """
`.....                                                 
`..   `..                                              
`..    `..   `..       `..    `. `..     `..    `. `...
`..    `.. `.   `..  `.   `.. `.  `..  `.   `..  `..   
`..    `..`..... `..`..... `..`.   `..`..... `.. `..   
`..   `.. `.        `.        `.. `.. `.         `..   
`.....      `....     `....   `..       `....   `...   
                              `..                      

{}  {}            {}                       
{}  {}      {}
{}  {}               {}
\_.------------------------------------------._/  
	""".format(D,CN,D,D,CB,D,D,VE,D)

	B3 = '''
   ___                     _ __                  
  |   \    ___     ___    | '_ \   ___      _ _  
  | |) |  / -_)   / -_)   | .__/  / -_)    | '_| 
  |___/   \___|   \___|   |_|__   \___|   _|_|_  
_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""| 
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 

{}  {}            {}                       
{}  {}      {}
{}  {}               {}
\_.------------------------------------------._/  
	'''.format(D,CN,D,D,CB,D,D,VE,D)
	
	B4 = """
===============================================
=       =======================================
=  ====  ======================================
=  ====  ======================================
=  ====  ===   ====   ===    ====   ===  =   ==
=  ====  ==  =  ==  =  ==  =  ==  =  ==    =  =
=  ====  ==     ==     ==  =  ==     ==  ======
=  ====  ==  =====  =====    ===  =====  ======
=  ====  ==  =  ==  =  ==  =====  =  ==  ======
=       ====   ====   ===  ======   ===  ======
===============================================                                                                 
\_.------------------------------------------._/ 
""" 

# force

	w = Fore.LIGHTRED_EX+" S   E   C   R   E   T   K   E   Y "+Style.RESET_ALL
	Li = Fore.LIGHTCYAN_EX+'\_.---------------------------------._/'+Style.RESET_ALL
	Lii = Fore.LIGHTRED_EX+'\_.---------------------------------._/'+Style.RESET_ALL
	B5 = """{}
{}
19  99  17  C8  96  77  60  9B  3B  0F  
1B  AB  82  3F  28  7D  34  62  3B  B2 
55  B8  EC  FC  51  51  F2  B7  D4  19  
9F  B2  A0  EF  27  34  E4  33  8F  AD
84  4D  3C  1C  48  27  4E  1D  94  46 
9D 5B 87 FF 29 32 EA AD 89 87 60 73 2D 
	        BE
{}
""".format(w,Li,Lii)

	erwl = Fore.GREEN+'--->'+Style.RESET_ALL+'\n'+Fore.GREEN+'_________________________________________________________________________'+Fore.LIGHTMAGENTA_EX
	erwl+='\n'+Fore.GREEN+'_______________________________________________________________________________'+Fore.LIGHTMAGENTA_EX
	erw = Fore.YELLOW+'\n\nC O D E  '+Fore.LIGHTRED_EX +'0x80004005 '+Fore.LIGHTCYAN_EX+' K E Y C O R R U P T E D '+Style.RESET_ALL
	erw+='\n'+Fore.GREEN+r'--->'+Style.RESET_ALL+'\n'+Fore.GREEN+'_________________________________________________________________________'+Style.RESET_ALL
	erw+='\n'+Fore.GREEN+'_______________________________________________________________________________'+Style.RESET_ALL
	Error_Bannr =Fore.LIGHTMAGENTA_EX+ """
{}
 ____                                   ______                       
|            |`````````, |`````````,  .~      ~.  |`````````,        
|______      |'''|'''''  |'''|'''''  |          | |'''|'''''         
|            |    `.     |    `.     |          | |    `.            
|___________ |      `.   |      `.    `.______.'  |      `.   {}        
	                                                                     
""".format(erwl,erw)+Style.RESET_ALL 

	                                                                                                                                                                                                                                                                                                                                                                                                  

	HS_W = Fore.LIGHTRED_EX +Back.BLUE+' D E E P E R '+Style.RESET_ALL
	HS = Fore.LIGHTYELLOW_EX+'%%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%'+Style.RESET_ALL
	HS+='\n'+Fore.LIGHTRED_EX+'%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'+Style.RESET_ALL
	HS+='\n'+'%%%%%%%     %%%%%%%%%     %%%%%%%%%%     %%%%%%%%%%%%%%%'+Style.RESET_ALL
	HS+='\n'+'%%%%%%%%%%'+ HS_W  +'%%%%%%%%%%%%%%%%%%%'
	HS+='\n'+'%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'+Style.RESET_ALL
	HS+='\n'+'%%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%'+Style.RESET_ALL
	HS+='\n'+'%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'+Style.RESET_ALL
	HS+='\n'+Fore.LIGHTGREEN_EX+'%%%%%%%     %%%%%%%%%     %%%%%%%%%%     %%%%%%%%%%%%%%%'+Style.RESET_ALL
	HS+='\n'+Fore.LIGHTMAGENTA_EX+'%%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%'+Style.RESET_ALL
	B6 =  HS

	B7 = '''
  ooo,    .---.
 o`  o   /    |\________________
o`   'oooo()  | ________   _   _)
`oo   o` \    |/        | | | |
  `ooo'   `---'         "-" |_|
                                RSA
{}  {}            {}                       
{}  {}      {}
{}  {}               {}  
\_.------------------------------------------._/ 
'''.format(D,CN,D,D,CB,D,D,VE,D) 

		
	
	CODE_BANNERCN = '['+Fore.GREEN+'--'+Style.RESET_ALL+"]  "+Fore.LIGHTCYAN_EX+' CodeName: '+Style.RESET_ALL+":"+Fore.LIGHTRED_EX+"HACkCrX"+Style.RESET_ALL+'                   ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	CODE_BANNER = '['+Fore.GREEN+'--'+Style.RESET_ALL+"]   "+Fore.LIGHTCYAN_EX+'        Created By'+Style.RESET_ALL+":"+Fore.LIGHTRED_EX+'  AhmedBalaha'+Style.RESET_ALL+'     ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	CODE_BANNERV = '['+Fore.GREEN+'--'+Style.RESET_ALL+"]  "+Fore.LIGHTCYAN_EX+'         Version'+Style.RESET_ALL+":"+Fore.LIGHTRED_EX+'  4.0.0'+Style.RESET_ALL+'              ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	

	
	Code_BA3 = r'(___._/  \_.___)'
	Code_BA1 = '['+Fore.GREEN+'--'+Style.RESET_ALL+']'+'._______________________________________'+'['+Fore.GREEN+'--'+Style.RESET_ALL+"]" 
	Code_BA2 = '['+Fore.GREEN+'--'+Style.RESET_ALL+']'+'\_.----------------------------------._/'+'['+Fore.GREEN+'--'+Style.RESET_ALL+"]" 
	GithubA = '['+Fore.GREEN+'--'+Style.RESET_ALL+"]"+r'      Follow Me On Github:' +Fore.LIGHTRED_EX+" HACkCrX"+Style.RESET_ALL+'      ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	FB = '['+Fore.GREEN+'--'+Style.RESET_ALL+"]"+r'         FB:' +Fore.LIGHTRED_EX+"   FB/ahmedbalaha115"+Style.RESET_ALL+'        ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	P = '['+Fore.GREEN+'--'+Style.RESET_ALL+"]"+r'      Select An Option To Begin'+   '         ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	

	CODE_BANNERT = ' ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"+r'   D#P13X0653FEAD10920D8C1972C3AC3F7E'+   '   ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	CODE_BANNERT1 = ' ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"+r'   D E E P E R E N C F I L E S E A X  '+   '  ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	CODE_BANNERT2 = ' ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"+r'   -----BEGIN RSA PRIVATE KEY-----  '+   '    ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	CODE_BANNERT3 = ' ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"+r'   Add Private Key To Safe Place   '+   '     ['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	CODE_BTS = [CODE_BANNERT,CODE_BANNERT1,CODE_BANNERT2,CODE_BANNERT3]
	CODE_BANNERTRAND =  random.choice(CODE_BTS)
	



	eye = Fore.GREEN+'<> <>'+Style.RESET_ALL
	H = Fore.GREEN+'R S A'+Style.RESET_ALL
	SH = Fore.LIGHTRED_EX+r'DC:\>Ｄ Ｅ Ｅ Ｐ Ｅ Ｒ ＄ Ｍ Ｅ Ｎ Ｕ ＠ Ｓ Ｈ Ｅ Ｌ Ｌ >'+Style.RESET_ALL
	

	if System=='Windows':
		L = Fore.LIGHTCYAN_EX+'\_.---------------------------------._/'+Style.RESET_ALL

	elif System=='Linux':
		L = Fore.LIGHTCYAN_EX+'\_.---------------------------------------------------._/'+Style.RESET_ALL


	B8 = ("""{}
{}
    ,-----.
   ( {} )
    )_ W _(	
     |||||    {}       {}
      |||     | | |	   {}
   __/)'(\__  `-+-'	   {}
  /\\     //\   |	   {}
 | |\\___//\ \  |	   {}
 | |/\\_//\ \ \ |	   {}
 | ||\\_//|  \ \|	   {}
 | ||/\_/\|   \ |	   {}
 | |/ /|\ \    \_)	   {}
 (_/  \_/  \    0
   |()| |()|    X
   \__/ \__/    0""".format(SH,L,eye,H,CODE_BANNERTRAND,CODE_BANNERCN,CODE_BANNER,CODE_BANNERV,GithubA,FB,P,Code_BA1,Code_BA2))

	

	# |)33P3R (RYPT0
	# 𝓓𝓮𝓮𝓹𝓮𝓻 𝓒𝓻𝔂𝓹𝓽𝓸
	# Ⓓⓔⓔⓟⓔⓡ Ⓒⓡⓨⓟⓣⓞ
	# ⒟⒠⒠⒫⒠⒭ ⒞⒭⒴⒫⒯⒪
	# ĐɆɆ₱ɆⱤ ₵ⱤɎ₱₮Ø
	Li = Fore.LIGHTCYAN_EX+'\_.-------------------------------------._/'+Style.RESET_ALL
	B9= """{}
	
 42  4E  D9  29  2C  43  42  C2  3D  5G  84
 08  63  3C  E6  F6  93  96  C8  FB  C4  45  
 62  A6  3F  C3  03  E7  AN  BO  RO  38  R7
 00  10  1D  CC  6C  21  C6  4C  1A  F1  G9
 FF  F3  00  E2  62  55  FB  56  55  3T  E5
 3E  F7  39  F1  45  D7  64  C3  D3  O5  A2
 E7  80  FF  E3  BA  45  32  52  F0  D0  W1
 D3  D5  95  A6  F8  C0  34  F8  A5  V1  00
 34  C7  F9  18  ED  CC  0F  BB  F5  RT  FF
{} """.format(SH,Li)


	Li = Fore.LIGHTCYAN_EX+'\_.--------------------------._/'+Style.RESET_ALL
	KEY = Fore.LIGHTCYAN_EX+'K E Y'+Style.RESET_ALL
	B10 = """{}

  PPPPP   IIIIIII   N    N
  P   PP     I      NN   N   	{}
  P   PP     I      N N  N
  PPPPP      I      N  N N      
  P          I      N   NN
  P       IIIIIII   N    N

  Strike a key when ready ...
  {}
	""".format(SH,KEY,Li)

	Text = Fore.LIGHTRED_EX+'error 23553261.... pending.....\nfatal ER # 5444167QW32Z__WS@&$$'+Style.RESET_ALL
	w = Fore.LIGHTGREEN_EX+'E R R O R  :  E M E R G E N C Y   S Y S T E M   F A I L U R E '+Style.RESET_ALL
	a = Fore.LIGHTRED_EX +Back.BLUE+'Alert'+Style.RESET_ALL
	li = Fore.LIGHTRED_EX+'\_.-----------------------------------------------------------._/'+Style.RESET_ALL

	The_mat = """
 _______________________________________________________________
[_[_]______________________{}____________________________[___]
[															 			 ]
[ {} ]
{}
{}	
 """.format(a,w,li,Text)



	PR1_w = '______________________________________________'
	PR1_w +='\n'+ '| >'+Fore.YELLOW+' QUERY FOR CLEARANCE '+Style.RESET_ALL+'                     |'+'\n'+'|'+Fore.RED+' .... '+Style.RESET_ALL+'                                      |'
	PR1_w+='\n'+'|'+Fore.RED+' ACCESS DENIED'+Style.RESET_ALL+'		                     |'
	PR1_w+='\n'+'| > INITIATE BATTERING RAM'+'		     |'
	PR1_w+='\n'+'|'+Fore.LIGHTCYAN_EX+' <A>NEV/HJS<KBA>(NET1=3V)MB1 -NK'+Style.RESET_ALL+'            |'
	PR1_w+='\n'+'| (BEM)RAMJET/SYPHON -XP FUNCTIONS           |'+'\n'+'|'+Fore.LIGHTYELLOW_EX+' TO SECONDRAY SYSTEMS {WATC} DEL SHA '+Style.RESET_ALL+'       |'
	PR1_w+='\n'+'|'+Fore.LIGHTRED_EX+' --SOFTWARE OVERRIDE....'+Style.RESET_ALL+'		     |'
	PR1_w+='\n'+'|'+Fore.YELLOW+' <P> PROGRAM - SYPHON/CIT  '+Style.RESET_ALL+'		     |'
	PR1_w+='\n'+'|'+Fore.YELLOW+' <C> MUTAGENIC RESARCH FILES/NES%clr'+Style.RESET_ALL+'	     |'
	PR1_w+='\n'+'|'+Fore.MAGENTA+' TO-<B> SWITCH K*CODE/MEMORY ALPHA'+Style.RESET_ALL+'          |'
	PR1_w+='\n'+'|'+Fore.YELLOW+' NULL/NOID PROCESS0045 '+Style.RESET_ALL+'		     |'
	PR1_w+='\n'+'|'+Fore.RED+' SECURITY SYSTEM DISABLED'+Style.RESET_ALL+'		     |'
	PR1_w+='\n'+ '|____________________________________________|'

	prg2 = Fore.RED+'5/OS Main Menu'+Style.RESET_ALL+'   System:'+Fore.YELLOW+'OSYS1'+Style.RESET_ALL
	prg2+='\n'+'Select one of the following:'
	prg2+='\n'+"""
	1. User tasks
	2. Office tasks
	3. General system tasks
	4. File, libraries, and folders
	5. Programming
	6. Communications
	90. Sign off
	Selection or command:
	"""
	prg2+='\n'+Fore.GREEN+'===>'+Style.RESET_ALL+'\n'+Fore.GREEN+'_________________________________________________________________________'+Style.RESET_ALL
	prg2+='\n'+Fore.GREEN+'_______________________________________________________________________________'+Style.RESET_ALL
	prg2+='\n'+Fore.BLUE+'F3=Exit   F4=Prompt   F9=Retrieve   F12=Cancel   F13=Information Assistant'+Style.RESET_ALL
	prg2+='\n'+Fore.YELLOW+'F23=Set initial menu'+Style.RESET_ALL

	cics_01 = Fore.LIGHTYELLOW_EX+r'DC:\>Ｄ Ｅ Ｅ Ｐ Ｅ Ｒ ＄ Ｍ Ｅ Ｎ Ｕ ＠ Ｓ Ｈ Ｅ Ｌ Ｌ >'+Style.RESET_ALL
	cics_01 +='\n''COMMAND ===>'+Fore.RED+'............'+Style.RESET_ALL+'              SCROLL ===>'+Fore.RED+'FULL'+Style.RESET_ALL
	cics_01+='\n''* '+Fore.CYAN+'Compiled:'+Style.RESET_ALL+'13.42.52'+Fore.CYAN+'hrs on'+Style.RESET_ALL+ '07/28/89..'+Fore.CYAN+'Link-Edited on:'+Style.RESET_ALL+'28JUL 89'+Fore.CYAN+'(00002K   )'+Style.RESET_ALL
	cics_01+='\n'+Fore.YELLOW+'l000132  001110     PERFORM CLEAR-RECORD-ITEMS.'
	cics_01+='\n''l000133  001120     PERFORM GET-NEXT-SCREEN-DATA.'
	cics_01+='\n''l000134  001130'+Style.RESET_ALL
	cics_01+='\n'+Fore.LIGHTYELLOW_EX+'=PAUS=   001200 MAIN-PROC SECTION.'+Style.RESET_ALL
	cics_01+='\n''l000138  001230                                                        ROUNDED.'+Style.RESET_ALL
	cics_01+='\n''--'+Fore.LIGHTYELLOW_EX+'lASSOC.DATA'+Style.RESET_ALL+' -----------------------------------------------------------------'
	cics_01+='\n'+Fore.YELLOW+'000017  000500 77  ENC AES DES 9(3)V2(2).'+Style.RESET_ALL+ 'x==>'+Fore.RED+'0000000000'+Style.RESET_ALL
	cics_01+='\n'+Fore.YELLOW+'000028  000655 66  Private KEY OFSET  PIC 9(2)V9(4).'+Style.RESET_ALL+'===>'+Fore.RED+'011250'+Style.RESET_ALL
	cics_01+='\n''-------------------------------------------------------------------------------'
	cics_01+='\n'+Fore.YELLOW+'000140  001250                                                        ROUNDED.'
	cics_01+='\n''--'+Fore.LIGHTYELLOW_EX+  'lCURRENT STATUS'+Style.RESET_ALL+' ------------------------------------------------'+Fore.CYAN+'Amode:'+Style.RESET_ALL+' 24 --'
	cics_01+='\n''|'+Fore.CYAN+' Reason for Halt:'+Fore.RED+'        SINGLE CYCLE HALT'+Fore.CYAN+'    PHASE' +Style.RESET_ALL
	cics_01+='\n''|'+Fore.CYAN+' Encryption 001337       RSA #F 1E 0D X1 RT K5  )'+Style.RESET_ALL +'		             |'
	cics_01+='------------------------------------------------------------------------------'
	####################################################################################################
	chappie = Fore.YELLOW+'Collect sub-programs and begin master compile? (Y/N) : Y'+Style.RESET_ALL
	chappie+='\n'+'** Loading AI components **'
	chappie+='\n'+'Bootstrap'+Fore.RED+'  -  -  -'+Fore.LIGHTCYAN_EX +'  OK'+Style.RESET_ALL
	chappie+='\n'+'Sensors'+Fore.RED+'    -  -  -'+Fore.LIGHTCYAN_EX +'  OK'+Style.RESET_ALL
	chappie+='\n'+'Speech'+Fore.RED+'     -  -  -'+Fore.LIGHTCYAN_EX +'  OK'+Style.RESET_ALL
	chappie+='\n'+'Volition'+Fore.RED+'   -  -  -'+Fore.LIGHTCYAN_EX +'  OK'+Style.RESET_ALL
	chappie+='\n'+'Knowledge'+Fore.RED+'  -  -  -'+Fore.LIGHTCYAN_EX +'  OK'+Style.RESET_ALL
	chappie+='\n'+'Motorium'+Fore.RED+'   -  -  -'+Fore.LIGHTCYAN_EX +'  OK'+Style.RESET_ALL
	chappie+='\n'+Fore.LIGHTYELLOW_EX+'Activating MAIN AI NETWORK....'+Style.RESET_ALL
	chappie+='\n'+Fore.LIGHTYELLOW_EX+'Progress: 100%'+Style.RESET_ALL
	chappie+='\n'+Fore.LIGHTYELLOW_EX+'Main Program Loop Stable'+Style.RESET_ALL
	chappie+='\n'+Fore.LIGHTRED_EX+'Found Error 23507.... pendingfatal ER # 5444167QW32Z__WS@&$$'+Style.RESET_ALL
	chappie+='\n'+Fore.CYAN+'Try To Fix Errors....'+Style.RESET_ALL
	chappie+='\n'+Fore.CYAN+'Faild To Fix pendingfatal ER # 5444167QW32Z__WS@&$$  '+Style.RESET_ALL
	chappie+='\n'+Fore.YELLOW+'Run RkCheker Force Fixing Errors - - - Status [Checking] '+Style.RESET_ALL
	chappie+='\n'+Fore.YELLOW+'Fixing pendingfatal ER # 5444167QW32Z__WS@&$$ Status [OK] '+Style.RESET_ALL
	chappie+='\n'+Fore.YELLOW+'CONCIOUSNESS.DAT Stable '+Style.RESET_ALL
	###################################################################
	B11 = "Unable to handle kernel NULL pointer dereference at virtual address 0xd34db33f"
	B11+= '\n'+'EFLAGS:'+Fore.CYAN+'00010046'+Style.RESET_ALL
	B11+= '\n'+'eax:'+Fore.LIGHTYELLOW_EX+ '00000001'+Style.RESET_ALL+' ebx:'+Fore.LIGHTYELLOW_EX+ 'f77c8c00'+Style.RESET_ALL+' ecx:'+Fore.YELLOW+ '00000000'+Style.RESET_ALL+ 'edx:'+Fore.LIGHTYELLOW_EX+' f77f0001'+Style.RESET_ALL
	B11+= '\n'+'esi:'+Fore.RED+'803bf014'+Style.RESET_ALL+' edi:'+Fore.LIGHTRED_EX+' 8023c755' +Style.RESET_ALL+' ebp:'+Fore.YELLOW+'80237f84'+Style.RESET_ALL+' esp:'+Fore.YELLOW+'80237f60'+Style.RESET_ALL
	B11+= '\n'+'ds:'+Fore.LIGHTYELLOW_EX+ '0018'+Style.RESET_ALL+  'es:'+Fore.LIGHTRED_EX+' 0018'+Style.RESET_ALL+  'ss:'+Fore.RED+ '0018'+Style.RESET_ALL
	B11+= '\n'+'Process Swapper (Pid:'+Fore.LIGHTGREEN_EX+ '0'+Style.RESET_ALL+', process nr:'+Fore.LIGHTGREEN_EX+ '0'+Style.RESET_ALL+', stackpage='+Fore.LIGHTGREEN_EX+ '80377000'+Style.RESET_ALL+')'
	B11+= '\n'+'Stack:'
	B11+= '\n'+Fore.LIGHTMAGENTA_EX+'..........................'+Style.RESET_ALL
	#B11+= '\n'+Fore.RED+'cccccccccccccccccccccccccc'+'\n'+'cccccccccccccccccccccccccc'+'\n'+Fore.LIGHTMAGENTA_EX+'.................'+Style.RESET_ALL+Fore.RED+'ccccccccc'+Style.RESET_ALL
	#B11+= '\n'+Fore.RED+'cccccccccccccccccccccccccc'+'\n'+'cccccccccccccccccccccccccc'+Style.RESET_ALL+Fore.LIGHTMAGENTA_EX+'\n'+'..........................'+Style.RESET_ALL
	B11+= '\n'+Fore.LIGHTYELLOW_EX+'ffffffffffffffffffffffffff'+'\n'+'ffffffff'+Style.RESET_ALL+Fore.LIGHTMAGENTA_EX+'..................'+Style.RESET_ALL
	B11+= '\n'+Fore.YELLOW+'ffffffffffffffffffffffffff'+'\n'+'ffffffff'+Style.RESET_ALL+Fore.LIGHTMAGENTA_EX+'..................'+Style.RESET_ALL
	B11+= '\n'+Fore.YELLOW+'ffffffff'+Style.RESET_ALL+'\n'+Fore.LIGHTMAGENTA_EX+'..................'+Style.RESET_ALL+'\n'+Fore.YELLOW+'ffffffff'+Style.RESET_ALL+'\n'+Fore.LIGHTMAGENTA_EX+'..................'+Style.RESET_ALL
	B11+= '\n'+'Code: 00 00 00 00 M3 T4 SP L0 1T FR 4M 3W OR K! V3 R5 I0 N5 00 00 00 00'
	B11+= '\n'+Fore.RED+'Kernel panic: Attempted to kill the idle task!'+Style.RESET_ALL
	B11+= '\n'+Fore.LIGHTCYAN_EX+'In swapper task - not syncing'+Style.RESET_ALL

	skftext = Fore.LIGHTWHITE_EX +Back.BLUE+'T4'+Style.RESET_ALL
	skftext1 = Fore.LIGHTWHITE_EX +Back.BLUE+'42'+Style.RESET_ALL
	skftext2 = Fore.LIGHTWHITE_EX +Back.BLUE+'M3'+Style.RESET_ALL
	skftext3 = Fore.LIGHTWHITE_EX +Back.BLUE+'P1'+Style.RESET_ALL
	skftext4 = Fore.LIGHTWHITE_EX +Back.BLUE+'40'+Style.RESET_ALL
	
	
	skf = """

[                             B8  42  4E  D9  29  2C    ]
[                             4F  08  63  3C  E6  F6    ]
[                             3D  {}  43  {}  C2  3D    ]
[                             22  93  96  C8  FB  T5    ]
[                             62  A6  3F  C3  03  E7    ]
[                             00  10  1D  CC  6C  21    ]
..............................GR  AN  BO  RO  UG  HV    ]
[                             C6  4C  1A  1E  8A  83    ]
[                             FF  F3  00  E2  62  55    ]
[                             FB  56  55  3E  F7  39    ]
[                             F1  45  D7  64  C3  D3    ]
[                             E7  80  {}  FF  E3  BA    ]
[                             45  32  52  F0  {}  Y1    ]
[                             D3  D5  95  A6  F8  C0    ]
[                             {}  34  F8  A5  34  C7    ]
[                             DC  F9  18  ED  CC  0F    ]
[                             BB  F5  11  FF  30  31    ]
""".format(skftext,skftext1,skftext2,skftext3,skftext4)
	ap = Fore.RED+"""
              .,-:;//;:=,
            . :H@@@MM@M#H/.,+%;,
         ,/X+ +M@@M@MM%=,-%HMMM@X/,
       -+@MM; $M@@MH+-,;XMMMM@MMMM@+-
      ;@M@@M- XM@X;. -+XXXXXHHH@M@M#@/.
    ,%MM@@MH ,@%=             .---=-=:=,.
    =@#@@@MX.,                -%HX$$%%%:;
   =-./@M@M$                   .;@MMMM@MM:
   X@/ -$MM/                    . +MM@@@M$
  ,@M@H: :@:                    . =X#@@@@-
  ,@@@MMX, .                    /H- ;@M@M=
  .H@@@@M@+,                    %MM+..%#$.
   /MMMM@MMH/.                  XM@MH; =;
    /%+%$XHH@$=              , .H@@@@MX,
     .=--------.           -%H.,@@@@@MX,
     .%MM@@@HHHXX$$$%+- .:$MMX =M@@MM%.
       =XMMM@MM@MM#H;,-+HMM@M+ /MMMX=
         =%@M@M#@$-.=$@MM@@@M; %M%=
           ,:+$+-,/H#MMMMMMM@= =,
                 =++%%%%+/:-.
	"""+Style.RESET_ALL
	ap+="\n"+Fore.GREEN+'<--^______________________________________________________________^-->'+Style.RESET_ALL
	ap+="\n"+Fore.LIGHTRED_EX+'     <--^D E E P E R C R R S A E N C S H E L L^--> SHELL$>'+Style.RESET_ALL
	ap+="\n"+Fore.GREEN+'<--^______________________________________________________________^-->'+Style.RESET_ALL



	Hllw = Fore.LIGHTRED_EX+"""
	           __
                  |  |
                  |  |
              ___/____\___
         _- ~              ~  _
      - ~                      ~ -_
    -                               _
  -         /\            /\          _
 -         / *\          / *\          _
_         /____\        /____\          _
_                  /\                   _
_                 /__\                  _
_      |\                      /|       _
 -     \ `\/\/\/\/\/\/\/\/\/\/' /      _
  -     \                      /      -
    ~    `\/^\/^\/^\/^\/^\/^\/'      ~
      ~                            -~
       `--_._._._._._._._._._.._--'
"""+Style.RESET_ALL
	#Hllw+='\n'+Fore.LIGHTMAGENTA_EX+'<..............................................>'+Style.RESET_ALL

	comte = Fore.LIGHTRED_EX+'DC\:> SHELL ENC DEEPER @ SHELL$>>> '+Fore.LIGHTBLUE_EX
	Com = Fore.LIGHTBLUE_EX+"""
		 _______________
		|  ___________  |   
		| |           | |  
		| |   0   0   | |   
		| |     -     | |   {}
		| |   \___/   | |
		| |___     ___| |
		|_______________|
		|_______________|
		/ **************\                  
		/ ************** \         
		<----------------->     
		\_....------...._/       
""".format(comte) +Style.RESET_ALL
	Com+='\n'+Fore.LIGHTRED_EX+'    <..............................................>'+Style.RESET_ALL


	
	
	
	CN = Fore.LIGHTCYAN_EX+'   CodeName: '+Style.RESET_ALL+":"+Fore.LIGHTRED_EX +"   HACkCrX"+Style.RESET_ALL
	CB = Fore.LIGHTCYAN_EX+'   Created By'+Style.RESET_ALL+":"+Fore.LIGHTRED_EX+'   AhmedBalaha'+Style.RESET_ALL
	VE = Fore.LIGHTCYAN_EX+'   Version'+Style.RESET_ALL+":"+Fore.LIGHTRED_EX+'      4.0.0'+Style.RESET_ALL
	FB =  Fore.LIGHTCYAN_EX+r'   FB:' +Fore.LIGHTRED_EX+"           FB/ahmedbalaha115"+Style.RESET_ALL
	Code_BA1 = '['+Fore.GREEN+'--'+Style.RESET_ALL+']'+'._______________________________________'+'['+Fore.GREEN+'--'+Style.RESET_ALL+"]" 
	D = Fore.WHITE+'['+Fore.GREEN+'--'+Style.RESET_ALL+"]"
	dev1xcr1 =Fore.LIGHTCYAN_EX+ """
  |_|   ,
 ('.') ///
 <(_)`-/'
<-._/J L /  -bf-

{}{}                {}
{}{}            {}
{}{}                  {}
{}{}      {}
{}
 """.format(D,CN,D,D,CB,D,D,VE,D,D,FB,D,Code_BA1)
	
	Seclogin_w = Fore.LIGHTRED_EX +Back.BLUE+'D E e P e R $CrX Page Login'+Style.RESET_ALL
	Seclogin_u = Fore.RED+'Deeper'+Style.RESET_ALL
	Seclogin_p = Fore.RED+'*******'+Style.RESET_ALL
	Seclogin_c = 'Checking...'+' ['+Fore.LIGHTGREEN_EX+' OK'+Style.RESET_ALL+' ]'
	Seclogin_l = 'Login '+'[ '+Fore.LIGHTGREEN_EX+' Successfully'+Style.RESET_ALL+' ]'
	Seclogin_e = 'Assert: '+Fore.LIGHTYELLOW_EX+ '0322x1x01'+Style.RESET_ALL+' :es4 '+Fore.LIGHTRED_EX+ '0xx0x'+Style.RESET_ALL+' Kernal:'+Fore.YELLOW+' fffff0xfx0'+Style.RESET_ALL

	Seclogin = """
 ___________________________________________________________
|                                                           |
|             {}    		    |
|___________________________________________________________|
|                                                           |
|                                                           |
|                                                           |
|     User Name:          [  {}  ]                      |
|                                                           |
|     Password:           [  {} ]                      |
|                                                           |
|           {}                              |
|                                         	            |
|    	    {}                         |
|___________________________________________________________|
| {}           |                 
|___________________________________________________________|
""".format(Seclogin_w,Seclogin_u,Seclogin_p,Seclogin_c,Seclogin_l,Seclogin_e)

	###########################################
	one = Fore.LIGHTGREEN_EX+'1' +Style.RESET_ALL
	ze =  Fore.LIGHTGREEN_EX+'0' +Style.RESET_ALL
	a,l,e,r,t= 'A' , 'l' ,'e' , 'r' ,'t' 
	SYSFIL = '\n'+Fore.LIGHTGREEN_EX+"==========================="+Style.RESET_ALL
	SYSFIL += '\n'+Back.LIGHTBLACK_EX + Fore.LIGHTRED_EX+'S Y S T E M   F A I L U R E'+Style.RESET_ALL
	SYSFIL += '\n'+Fore.LIGHTGREEN_EX+'==========================='+Style.RESET_ALL
	SYSFIL += """

  {} 	  {}	 {}       {}  	   
  {}	  {}	 {}       {}   
  {}	  {}	 {}       {}	 
  {}	  {}	 {}	 {} 
  {}	  {}	 {}	 {}	 
  {}	  {}	 {}	 {}
  {}	  {}	 {}	 {}
  {}	  {}	 {}	 {}
  {}	  {}	 {}       {}
  {}	  {}	 {}	 {}
	""".format(one,ze,one,ze,one,ze,one,ze,one,ze,one,ze,one,ze,one,ze,one,ze,one,ze,one,one,ze,one,ze,one,ze,one,ze,one,ze,one,ze,one,ze,Fore.LIGHTGREEN_EX+a,l,e,r,t+Style.RESET_ALL)


	######################
	#H = Fore.LIGHTRED_EX+r'DC:\>Ｄ Ｅ Ｅ Ｐ Ｅ Ｒ ＄ B L A C K M E S A ＠ Ｓ Ｈ Ｅ Ｌ Ｌ >'+Style.RESET_ALL


	Hackesx01 = Fore.LIGHTGREEN_EX+'x006e7d44'+'94c24000000'+'   mav qword '+'['+Fore.LIGHTBLUE_EX+'VAR_1F0H'+Style.RESET_ALL+' rax'
	Hackesx02 = Fore.LIGHTGREEN_EX+'x006e7d44'+'94c24000000'+'   mav qword '+'['+Fore.LIGHTBLUE_EX+'VAR_1F0H'+Style.RESET_ALL+' rax'
	Hackesx03 = Fore.LIGHTGREEN_EX+'x006e7d44'+'94c24000000'+'   mav qword '+'['+Fore.LIGHTBLUE_EX+'VAR_1F0H'+Style.RESET_ALL+' rax'
	Hackesx04 = Fore.LIGHTRED_EX+'unswept  spangcjhelldogblobleRequestErrormpxs0x5e00'
	Hackesx05 = Fore.LIGHTGREEN_EX+'x006e7d44'+'94c24000000'+'   mav qword '+'['+Fore.LIGHTBLUE_EX+'VAR_1F0H'+Style.RESET_ALL+' rax'
	Hackesx06 = Fore.LIGHTGREEN_EX+'x006e7d44'+'94c24000000'+'   mav qword '+'['+Fore.LIGHTBLUE_EX+'VAR_1F0H'+Style.RESET_ALL+' rax'
	Hackesx07 = Fore.LIGHTGREEN_EX+'x006e7d44'+'94c24000000'+'   mav qword '+'['+Fore.LIGHTBLUE_EX+'VAR_1F0H'+Style.RESET_ALL+' rax'
	Hackesx08 = Fore.LIGHTRED_EX+'unswept  spangcjhelldogblobleRequestErrormpxs0x5e00'
	c = Fore.LIGHTYELLOW_EX+'Created By:  AhmedBalaha'+Style.RESET_ALL
	f = Fore.LIGHTCYAN_EX+'FB:  ahmedbalaha115'+Style.RESET_ALL
	X = Fore.LIGHTCYAN_EX+'Deeper Encryption PrKey Session %20################%100'+Style.RESET_ALL
	Finalhackesx = Hackesx01+'\n'+Hackesx02+'\n'+Hackesx03+'\n'+Hackesx04+'\n'+Hackesx05+'\n'+Hackesx06+'\n'+Hackesx07+'\n'+Hackesx08+'\n'+c+'\n'+f'\n'+X

	newbannerhallowedn2022 =Fore.LIGHTRED_EX+ '''
 From: t...@novell.com (Todd D. Hale)
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$PR$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$ Pumpkin $$$$$$$$$$$$$$$$$$$$$$"    @$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"      '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$                 """"""#*R$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$P"..::!~ .....    .<!!!!!!!:  ~!!!:.. "*$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$".<!!!!~  <!!!!!!!~ !!!!!!!!!!!!!  !!!!!!!: "$$$$$$$$$$$
$$$$$$$$$$$$$P <!!!!!~ .!!!!!!!!!! !!!!!!!!!!!!!!!. `!!!!!!!: "$$$$$$$$$
$$$$$$$$$$$P :!!!!!~ .!!!!~!!!!!! .!!!!!!!!!~!!!!!!: '!!!!!!!! '$$$$$$$$
$$$$$$$$$$# !!!!!f  !!!`   `!!!!! :!!!!!!!!!    `!!!! `!!!!!!!! '$$$$$$$
$$$$$$$$$F !!!!!!  !!~      '!!!f  4!!!!!!!!       !!> 4!!!!!!!> 9$$$$$$
$$$$$$$$P <!!!!!  !!>        '!!~   '!!!!!!........<!!  !!!!!!!! <$$$$$$
$$$$$$$$> !!!!!! ~!!!!!!!!!!!!!~      `!!!!!!!!!!!!!!!> `!!!!!!!  $$$$$$
$$$$$$$$ '!!!!!! '!!!!!!!!!!!!!!> !!!!!!!!!!!!!!(``~!!!  !!!!!!f 4$$$$$$
$$$$$$$$r!!!!!!! `!!~   :<!!!!!!! `!!!!!!!!!!!!!~    `! '!!!!!!> .$$$$$$
$$$$$$$$L !!!!!!. !!:h   `!!!!!!! `!!!!!!!!!~     <!!!!  !!!!!!  @$$$$$$
$$$$$$$$$ `!!!!!! ~!!!!       `~~ '~~~~~`        !!!!!f .!!!!!  <$$$$$$$
$$$$$$$$$N ~!!!!!! !!!!!h.           ..::     .!!!!!!!  :!!!!` .$$$$$$$$
$$$$$$$$$$$. ~!!!!> !!!!!!!!:       `!!!!!h!!!!!!!!!!~  !!!!  d$$$$$$$$$
$$$$$$$$$$$$N. `!!!. !!!!!!!!!!!!! ~!!!!!!!!!!!!!!!!~  !!~ .e$$$$$$$$$$$
$$$$$$$$$$$$$$$bu  `  '!!!!!!!!!!~  !!!!!!!!!!!!!~` .uuue$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$e.  ````   .eu.     ```   .e$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
'''+Style.RESET_ALL

	newxb = Fore.LIGHTCYAN_EX+"""
Subject:    Halloween Goodies!
From:       FB:ahmedbalaha65 (SuperMe!)
Date:       1/1/2022
Newsgroups: alt.ascii-art

anyone have any halloween treats?!

▀█████████▄     ▄████████  ▄█          ▄████████    ▄█    █▄       ▄████████ 
  ███    ███   ███    ███ ███         ███    ███   ███    ███     ███    ███ 
  ███    ███   ███    ███ ███         ███    ███   ███    ███     ███    ███ 
 ▄███▄▄▄██▀    ███    ███ ███         ███    ███  ▄███▄▄▄▄███▄▄   ███    ███ 
▀▀███▀▀▀██▄  ▀███████████ ███       ▀███████████ ▀▀███▀▀▀▀███▀  ▀███████████ 
  ███    ██▄   ███    ███ ███         ███    ███   ███    ███     ███    ███ 
  ███    ███   ███    ███ ███▌    ▄   ███    ███   ███    ███     ███    ███ 
▄█████████▀    ███    █▀  █████▄▄██   ███    █▀    ███    █▀      ███    █▀  
                          ▀                                                  

	"""+Style.RESET_ALL

	Black_mesa = Fore.GREEN+"""
    	   .-;+$XHHHHHHX$+;-.
          ,;X@@X%/;=----=:/%X@@X/,
        =$@@%=.              .=+H@X:
     -XMX:                      =XMX=
     /@@:                          =H@+
   %@X,       <>           <>       .$@$
  +@X.                               $@%%
 -@@,                <>                .@@=
  %@%                                  +@$
  H@:                                  :@H
  H@:         :HHHHHHHHHHHHHHHHHHX,    =@H
  %@%         ;@M@@@@@@@@@@@@@@@@@H-   +@$
  =@@,        :@@@@@@@@@@@@@@@@@@@@@= .@@:
   +@X        :@@@@@@@@@@@@@@@M@@@@@@:%@%
    $@$,      ;@@@@@@@@@@@@@@@@@M@@@@@@$.
     +@@HHHHHHH@@@@@@@@@@@@@@@@@@@@@@@+
      =X@@@@@@@@@@@@@@@@@@@@@@@@@@@@X=
        :$@@@@@@@@@@@@@@@@@@@M@@@@$:
                     """+Style.RESET_ALL








   


  
   
    
    
	Banners = [dev1xcr1,B1,Fore.BLUE+B2+Style.RESET_ALL,Fore.GREEN+B3,Fore.LIGHTRED_EX+B4+Style.RESET_ALL,Fore.LIGHTCYAN_EX+B5+Style.RESET_ALL,Fore.BLUE+B6+Style.RESET_ALL,Fore.CYAN+B7+Style.RESET_ALL,B8,B9,B10,The_mat,cics_01,
	
	Black_mesa,chappie,SYSFIL,B11,Seclogin,prg2,PR1_w,Error_Bannr,Hllw,Com,ap,skf,Finalhackesx,Fore.LIGHTCYAN_EX+newxb,Fore.LIGHTRED_EX+newbannerhallowedn2022]
	print(random.choice(Banners))
	
	




def main():
	Clean_Gen_Files()
	while True:
		clear()
		Banners_Style()
		print()
		print('['+Fore.CYAN+'1'+Style.RESET_ALL+']'+Fore.RED+'-'+Style.RESET_ALL+'['+Fore.CYAN+'Encryption'+Style.RESET_ALL+']')
		print('['+Fore.CYAN+'2'+Style.RESET_ALL+']'+Fore.RED+'-'+Style.RESET_ALL+'['+Fore.CYAN+'Decryption'+Style.RESET_ALL+']')
		print('['+Fore.CYAN+'3'+Style.RESET_ALL+']'+Fore.RED+'-'+Style.RESET_ALL+'['+Fore.CYAN+'Genrate Keys'+Style.RESET_ALL+']')
		print('['+Fore.CYAN+'4'+Style.RESET_ALL+']'+Fore.RED+'-'+Style.RESET_ALL+'['+Fore.CYAN+'DeeperCR Modes (Shell Mode)'+Style.RESET_ALL+']')
		print('['+Fore.CYAN+'5'+Style.RESET_ALL+']'+Fore.RED+'-'+Style.RESET_ALL+'['+Fore.CYAN+'Hide Keys'+Style.RESET_ALL+']')
		print('\n')

		try:
			
			if System=="Linux":

				print(Fore.RED+"┌─"+Style.RESET_ALL+'['+Fore.CYAN+':DeeperCrypto'+Style.RESET_ALL+'[──['+Fore.RED+'Menu'+Style.RESET_ALL+']:')
				print(Fore.RED+'└─────► '+Style.RESET_ALL,end="") ; ch=int(input())
				

			else:
				print('┌─'+Style.RESET_ALL+'['+Fore.CYAN+':DeeperCrypto'+Style.RESET_ALL+'[──['+Fore.RED+'Menu'+Style.RESET_ALL+']:',end="")
			
				ch = int(input())
				
			if ch==1:
				encryption()

			elif ch==2:
				Decryption()

			elif ch==3:
				try:
					if Counter==1:
						print(I,'Keys already Genrated ')
						print(I,'Press ENTER To [Return]',end="") ;input()
		
				except NameError:
					Genrate_Keys()

				else:
					Genrate_Keys()


			elif ch==4:
				
				clear()
				
				SHELL_MODE_STYLE()
				
				print()
				print(Mrakp,"Use help for help menu")
				print()
				while True:
					print('┌─'+Style.RESET_ALL+'['+Fore.CYAN+'Shell'+Style.RESET_ALL+Fore.RED+r'\> '+Style.RESET_ALL,end="")
					shell = input().split(' ')
					
					if shell[0] == "Set" and len(shell) == 3:
						Set(shell[1],shell[2])

					if shell[0]=='options':
						options()

					if shell[0]=='modeshelp':
						modeshelp()

					if shell[0]=='list':
						try:
							list(shell[1])
						except IndexError:
							pass

					elif shell[0]=='help':
						clear()
						helpmenu()

					elif shell[0]=='exit':
						clear()
						main()

					
					Modes = ['hash','enc','dec','hashhmac','crackhash']

					if shell[0]=='run':
						if mode=='hash':
							if algorithm=='':
								print('Proived Hash!')
								
							elif password=='':
								print('Proived Password!')
							else:
								run(algorithm,password,'hash',False,False,False,False,False,False,False,False,False,False,False,False)
								
						elif mode=="enc":
							if password=='':
								print('Proived Password!')

							elif publickey=='':
								print('Proived PublicKey!')
							elif privatekey=='':
								print('Proived PrivateKey!')
							if password!='' and publickey!='' and privatekey!='':
								run(False,password,'enc',saveplace,publickey,privatekey,False,False,False,False,False,False,False,False,False)
							
						elif mode == 'dec':
							if password=='':
								print('Proived Password!')
							elif publickey=='':
								print('Proived Public Key Path!')
							elif privatekey=='':
								print('Proived private Key Path!')
							if password!='' and publickey!='' and privatekey!='':
								run(False,password,'dec',saveplace,publickey,privatekey,False,False,False,False,False,False,False,False,False)
							
						elif mode=='hashhmac':
								if algorithm=='':
									print('Proived Hash!')
								
								elif password=='':
									print('Proived Password!')

								else:
									run(algorithm,password,'hashhmac',False,False,False,False,False,False,False,False,False,False,False,False)

						elif mode=='crackhash':
							if Crackmethod =='':
								print('Proived Crack Method Dictionary or Bruteforce Attack')

							elif Crackmethod=='dictionary':
								if Crhash=='':
									print('Proived Hash!')

								elif HashSalt=='':
									print('Proived Hash Salt!')

								elif wordlist=='':
									print('Proived wordlist!')
								#print(Crhash,HashSalt,wordlist)
								if Crhash !='' and HashSalt!='' and wordlist!='':
									run(False,Crhash,'crackhash',False,False,False,False,HashSalt,wordlist,Crackmethod,False,False,False,verbose,False)

								

							elif Crackmethod=="bruteforce":
								if Min==None:
									print('Proived Minimum Number Of Password!')

								elif Max==None:
									print('Proived Maximum Number Of Password!')


								elif Crhash=='':
									print('Proived Hash!')

								elif HashSalt=='':
									print('Proived Hash Salt!')

								elif Chars=='':
									print('Proived Chars!')

								if Crhash !='' and HashSalt!='' and Max != None and Min!=None and Chars!='':
									run(False,Crhash,'crackhash',False,False,False,False,HashSalt,wordlist,Crackmethod,Min,Max,Chars,verbose,False)
									# Hashfile

						elif mode=='crackzip':
							if Crackmethod=='dictionary':
								if wordlist=='':
									print('Proived Wordlist!')
								elif Zipfile=='':
									print('Proived Zip File!')

								if wordlist !='' and Zipfile!='':
									run(False,False,'crackzip',False,False,False,False,False,wordlist,Crackmethod,False,False,False,verbose,Zipfile)
							elif Crackmethod=='bruteforce':
								if Zipfile=='':
									print('Proived Zipfile!')
								elif Chars=='':
									print('Proived chars!')
								elif Min==None:
									print('Proived Min Password!')

								elif Max==None:
									print('Proived Max Password!')

								if Zipfile!='' and Chars!='' and Min!=None and Max!=None:
									run(False,False,'crackzip',False,False,False,False,False,False,Crackmethod,Min,Max,Chars,verbose,Zipfile)



					Commands = ['Set','run','list','help','options','exit','modeshelp']
					if shell[0] in Commands:
						pass
					elif shell[0]=='':
						continue

					else:
						print('[-] Command not found')

			elif ch==5:
				clear()
				print("""][-][ ]][ ][_) ]E   ][< ]E ``// ((5 
 _,_ _ __, __,   _,_ __, , _  _,
 |_| | | \ |_    |_/ |_  \ | (_ 
 | | | |_/ |     | \ |    \| , )
 ~ ~ ~ ~   ~~~   ~ ~ ~~~   )  ~ 
                              

					""")
				def isPython(versionNumber): # Check the version of python running
				    import platform
				    return platform.python_version().startswith(str(versionNumber))

				def consoleReadLine(message): # Read a string from the console
				    if isPython(3): # Python 3.x code
				        return input(message)
				    else: # Python 2.x code
				        return raw_input(message)

				def consoleWriteLine(message): # Write a string to the console
				    import os, sys
				    sys.stdout.write(str(message) + os.linesep)

				from platform import system
				operatingSystem = system()

				if operatingSystem == "Windows" or operatingSystem == "Darwin":
				    folderPath = consoleReadLine("[*] Enter The Path Of The Keys Folder You Want To Hide Or Unhide: ")
				    command = consoleReadLine("[*] Do You Want To hide Or unhide type: [hide|unhide]? '{0}': ".format(folderPath)).upper()
				    from subprocess import call
				    if command == "HIDE":
				        if operatingSystem == "Windows":
				            call(["attrib", "+H", folderPath])
				            print("""
_   _    _    __  ___   _      _____  _            
(_/ ) (|)  | |  (__    )  (|)       /\  (|) (_/_  (/) 
                                  ..'                  
				            	""")
				            input('[!] Hide Folder [OK] PRESS ENTER To CONTINUE ')
				        elif operatingSystem == "Darwin":
				            call(["chflags", "hidden", folderPath])
				    elif command == "UNHIDE":
				        if operatingSystem == "Windows":
				            call(["attrib", "-H", folderPath])
				            print("""
_   _    _    __  ___   _      _____  _            
(_/ ) (|)  | |  (__    )  (|)       /\  (|) (_/_  (/) 
                                  ..'                  
				            	""")
				            input('[!] Unhide Folder [OK] PRESS ENTER To CONTINUE ')
				        elif operatingSystem == "Darwin":
				            call(["chflags", "nohidden", folderPath])
				    else:
				        consoleWriteLine("ERROR: (Incorrect Command) Valid commands are 'HIDE' and 'UNHIDE' (both are not case sensitive)")
				else:
				    consoleWriteLine("ERROR: (Unknown Operating System) Only Windows and Darwin(Mac) are Supported")
			else:
				continue


		except ValueError:
			continue

			

		except KeyboardInterrupt:
			print()
			print("[+] Detecting [CTRL+C] Quiting.... ", end="")
			sleep(0.50)
			Clean_Gen_Files()
			clear()
			sys.exit()

		

if __name__ == '__main__':
	main()


