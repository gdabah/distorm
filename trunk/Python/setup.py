#!/usr/bin/env python

# Copyright (c) 2009, Mario Vilas
# All rights reserved.
# Licensed under GPLv3.
#

__revision__ = "$Id: setup.py 603 2010-01-31 00:11:05Z qvasimodo $"

import os
import sys
import shutil
import platform

from distutils.core import setup
from distutils.command.install_lib import install_lib

# Customized install_lib command to set the execution bit in some files
class custom_install_lib(install_lib):
    def install(self):
        outfiles = install_lib.install(self)
        for outfile in outfiles:
            if os.path.splitext(outfile)[1].lower() != '.py':
                print "setting mode 755 to %s" % outfile
                os.chmod(outfile, 0755)
        return outfile

def main():
    # Get the target platform
    arch    = platform.architecture()[0].lower()
    machine = platform.machine().lower()
    system  = platform.system().lower()
    if 'cygwin' in system:
        system = 'cygwin'
    elif 'darwin' in system:
        system = 'macosx'
    if machine.startswith('power'):
        machine = 'ppc'
    elif machine.endswith('86'):
        machine = 'x86'
    elif not machine:
        if system == 'macosx':
            if arch == '64bit':
                machine = 'x86_64'
            elif arch == '32bit':
                if sys.byteorder == 'little':
                    machine = 'x86'
                else:
                    machine = 'ppc'
        elif system == 'windows':
            if arch == '64bit':
                machine = 'amd64'
            else:
                machine = 'x86'
        else:
            if arch == '64bit':
                machine = 'x86_64'
            else:
                machine = 'x86'

    # Get the filename for the target platform
    if   system in ('windows', 'cygwin'):
        data = 'distorm3.dll'
    elif system in ('darwin', 'macosx'):
        data = 'libdistorm3.dylib'
    else:
        data = 'libdistorm3.so'

    # Parse the package root directory
    cwd = os.path.split(__file__)[0]
    if not cwd:
        cwd = os.getcwd()
    root = '%s-%s' % (system, machine)

    # Check if the package root directory exists
    if not os.path.exists(root):
        print "Error: unsupported platform (%s-%s)" % (system, machine)
        return

    options = {

    # Setup instructions
    'requires'          : ['ctypes'],
    'provides'          : ['distorm3'],
    'packages'          : ['distorm3'],
    'package_data'      : { 'distorm3' : [data, "sample.py"] },
    'package_dir'       : { 'distorm3' : root },
    'cmdclass'          : { 'install_lib' : custom_install_lib },

    # Metadata
    'name'              : 'distorm3',
    'version'           : '1.0',
    'description'       : 'The goal of diStorm3 is to decode x86/AMD64' \
                          ' binary streams and return a structure that' \
                          ' describes each instruction.',
    'long_description'  : (
                        'Powerful Disassembler Library For AMD64\n'
                        'by Gil Dabah (arkon@ragestorm.net)\n'
                        '\n'
                        'Python bindings by Mario Vilas (mvilas@gmail.com)'
                        ),
    'author'            : 'Gil Dabah',
    'author_email'      : 'arkon'+chr(64)+'ragestorm'+chr(0x2e)+'net',
    'maintainer'        : 'Gil Dabah',
    'maintainer_email'  : 'arkon'+chr(64)+'ragestorm'+chr(0x2e)+'net',
    'url'               : 'http://code.google.com/p/distorm/',
    'download_url'      : 'http://code.google.com/p/distorm/',
    'platforms'         : ['cygwin', 'win', 'linux', 'macosx'],
    'classifiers'       : [
                        'License :: OSI Approved :: GPLv3 License',
                        'Development Status :: 5 - Production/Stable',
                        'Intended Audience :: Developers',
                        'Natural Language :: English',
                        'Operating System :: Microsoft :: Windows',
                        'Operating System :: MacOS :: MacOS X',
                        'Operating System :: POSIX :: Linux',
                        'Programming Language :: Python :: 2.4',
                        'Programming Language :: Python :: 2.5',
                        'Programming Language :: Python :: 2.6',
                        'Topic :: Software Development :: Disassemblers',
                        'Topic :: Software Development :: Libraries :: Python Modules',
                        ],
    }

    # Change the current directory
    curdir = os.path.split(__file__)[0]
    if curdir:
        os.chdir(curdir)
        
    # Copy some files manually to the source directory, since distutils can't work with a few source dirs! grr
    shutil.copy("__init__.py", os.path.join(curdir, root, "__init__.py"))
    shutil.copy("sample.py", os.path.join(curdir, root, "sample.py"))

    # Call the setup function
    setup(**options)

if __name__ == '__main__':
    main()
