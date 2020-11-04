import sys
from urllib.request import urlopen
from os import system as cmd
import os
import platform
from time import sleep
import threading
import time
import urllib.request
from tqdm import tqdm
import os.path



System = platform.platform().split("-")[0]

loading = True 
loading_speed = 4  
loading_string = "." * 4

def Sp_Dots(text,stop):
	
	print(text,end="")
	while 1:
	    for index, char in enumerate(loading_string):
	        sys.stdout.write(char) 
	        sys.stdout.flush()  
	        sleep(1.0 / loading_speed)  
	    index += 1  
	    sys.stdout.write("\b" * index + " " * index + "\b" * index)
	    sys.stdout.flush()  # flush the output
	    if stop():
	    	break
 


class DownloadProgressBar(tqdm):
    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)



	
def clear():
	if System=='Windows':
		cmd('cls')
	else:
		cmd('clear')




def download_Update():
	cwd = os.getcwd()
	url = 'https://github.com/NoOAYe/deeperv4/archive/master.zip'
	filename = 'masterdeeper.zip'
	with DownloadProgressBar(unit='B', unit_scale=True,
                             miniters=1, desc='masterdeeper.zip') as t:
		urllib.request.urlretrieve(url, filename=filename, reporthook=t.update_to)
	FilePath = os.path.join(cwd,filename)
	print('[+] Download Complete!! File Save as {} '.format(FilePath))
	print('[!] PRESS ENTER TO RETURN TO CONTINUE (^.^): ',end="");input()


def updater():
	clear()
	stop_threads = False
	t1 = threading.Thread(target = Sp_Dots, args =('[*] Cheking For Updates',lambda : stop_threads, )) 
	t1.start() 
	sleep(2)

	Counter = '1'
	Crunt_Version = '4.0.0'
	try:
		Get_Version = urlopen('https://raw.githubusercontent.com/NoOAYe/deeperv4/master/Data/version.txt').read().decode('utf-8').strip()
		version	 = Get_Version[0:5]
		count = Get_Version[-1]

		


	except:
		print()
		print("[-] Can't reach Internet !!!")
		stop_threads = True
		t1.join() 
		sys.exit()
	print()
	stop_threads = True
	t1.join() 

	if version != Crunt_Version:
		print("[+] New Version Is Available!")
		sleep(2)
		if System=='Linux':
			try:
				cmd('git clone https://github.com/NoOAYe/deeperv4.git')
			except:
				pass
				download_Update()
				
		elif System=='Windows':
			try:
				clear()
				download_Update()

				
				
			except Exception as e:
				print(e)
	
		

	elif count != Counter	:
		print("[*] New Update Is Available!")
		sleep(2)
		if System=='Linux':
			try:
				cmd('git clone https://github.com/NoOAYe/deeperv4.git')
			except:
				pass
				download_Update()
		elif System=='Windows':
			try:
				clear()
				download_Update()
			except Exception as e:
				print(e)


		

	else:
		print('[*] No Updates Found')
		print('[!] PRESS ENTER TO RETURN TO CONTINUE (^.^): ',end="");input()








updater()
