#!/usr/bin/env python

import glob

from setuptools import setup

scripts = glob.glob('bin/*')


version="4.0.0"


setup(name="DeeperCr",
    version=version,
    license="GPL",
    author='N@RAMInA$_AKB',
    url="https://github.com/NoOAYe/deeperv4",
    install_requires=['Crypto==1.4.1','halo==0.0.30 ','colorama==0.4.3 ',
    'pycryptodome==3.9.8 ','yaspin','progressbar','tqdm'
     ],
    scripts = scripts
)


   
  
   
   
  
    
    
