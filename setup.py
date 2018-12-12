#!/usr/bin/env python

# Copyright (c) 2009, Mario Vilas
# Rob Ruana 2010
# Gil Dabah
# All rights reserved.
# Licensed under BSD.
#

__revision__ = "$Id: setup.py 603 2010-01-31 00:11:05Z qvasimodo $"

import re
import os
import os.path
import platform
import string
import shutil
import sys
import subprocess as sp

from glob import glob
from shutil import ignore_patterns
from setuptools import dist
from distutils import log
from distutils.command.build import build
from distutils.command.build_clib import build_clib
from distutils.command.clean import clean
from setuptools.command.install import install
from distutils.command.install_lib import install_lib
from distutils.command.sdist import sdist
from distutils.core import setup, Extension
from distutils.errors import DistutilsSetupError

def scanfor_vc_all():
 fname = "vcvarsall.bat"
 startDir = "C:\\Program Files (x86)\\Microsoft Visual Studio\\"
 print("searching for %s" % fname)
 for dirpath, dirnames, filenames in os.walk(startDir):
  for f in filenames:
   if f == fname:
    return os.path.join(dirpath, f)

def compile_vc(solution_path, config, platform):
    match_vs = re.compile('vs(\d+)comntools$', re.I).match
    compilers = [
        m.group(1, 0) for m in (match_vs(k) for k in os.environ.keys())
        if m is not None
    ]
    msbuild = [
        'msbuild',
            '/p:Configuration=%s' % config,
            '/p:Platform=%s' % platform,
            solution_path
    ]
    for ver, var in sorted(compilers, key = lambda v: -int(v[0])):
        bat = os.path.join(os.environ[var], r'..\..\vc\vcvarsall.bat')
        try:
            log.info('Compiling with %s: %s', var, ' '.join(msbuild))
            sp.check_call(['call', bat, '&&'] + msbuild, shell = True)
            return
        except sp.CalledProcessError:
            log.info('compilation with %s failed', var)
    # Try brute force find the batch file for VS env
    try:
        bat = scanfor_vc_all()
        log.info('Compiling with %s' % bat)
        sp.check_call(['call', bat, 'x86_amd64' if platform=='x64' else 'x86', '&&'] + msbuild, shell = True)
        return
    except sp.CalledProcessError:
        log.info('compilation failed')

    raise DistutilsSetupError(
        'Failed to compile "%s" with any available compiler' % solution_path
    )

def get_sources():
    """Returns a list of C source files that should be compiled to 
    create the libdistorm3 library.
    """
    return sorted(glob('src/*.c'))

class custom_build(build):
    """Customized build command"""
    def run(self):
        log.info('running custom_build')
        if 'windows' in platform.system().lower():
            bits = 'win32' # x86 by default
            # If x64 is specified in command line, change it here
            for i in sys.argv:
                if i.find("--plat-name=win-amd64") != -1:
                     bits = 'x64'
            compile_vc('make/win32/distorm.sln', 'dll', bits)
            self.copy_file('distorm3.dll', 'python/distorm3')
        build.run(self)

class custom_build_clib(build_clib):
    """Customized build_clib command

    This custom_build_clib will create dynamically linked libraries rather 
    than statically linked libraries.  In addition, it places the compiled 
    libraries alongside the python packages, to facilitate the use of ctypes. 
    """

    def finalize_options(self):
        # We want build-clib to default to build-lib as defined by the 
        # "build" command.  This is so the compiled library will be put 
        # in the right place along side the python code.
        self.set_undefined_options('build',
                                   ('build_lib', 'build_clib'),
                                   ('build_temp', 'build_temp'),
                                   ('compiler', 'compiler'),
                                   ('debug', 'debug'),
                                   ('force', 'force'))

        self.libraries = self.distribution.libraries
        if self.libraries: # In Python 3.0 they have a bug in check_library_list, comment it out then.
            self.check_library_list(self.libraries)

        if self.include_dirs is None:
            self.include_dirs = self.distribution.include_dirs or []
        if type(self.include_dirs) in (bytes, str):
            self.include_dirs = string.split(self.include_dirs,
                                             os.pathsep)

    def get_source_files_for_lib(self, lib_name, build_info):
        sources = build_info.get('sources', [])
        if hasattr(sources, '__call__'):
            sources = sources()
        if (sources is None or
            type(sources) not in (list, tuple) or
            len(sources) == 0):
            raise DistutilsSetupError(
                "in 'libraries' option (library '%s'), 'sources' must be "
                "present and must be a list of source filenames" % lib_name
            )
        return sources

    def get_source_files(self):
        self.check_library_list(self.libraries)
        filenames = []
        for (lib_name, build_info) in self.libraries:
            sources = self.get_source_files_for_lib(lib_name, build_info)
            filenames.extend(sources)
        return filenames

    def run(self):
        log.info('running custom_build_clib')
        build_clib.run(self)

    def build_libraries(self, libraries):
        for (lib_name, build_info) in libraries:
            sources = self.get_source_files_for_lib(lib_name, build_info)
            sources = list(sources)

            log.info("building '%s' library", lib_name)

            # First, compile the source code to object files in the 
            # library directory.
            macros = build_info.get('macros')
            include_dirs = build_info.get('include_dirs')
            objects = self.compiler.compile(sources,
                output_dir=self.build_temp,
                macros=macros,
                include_dirs=include_dirs,
                extra_postargs=build_info.get('extra_compile_args', []),
                debug=self.debug)

            # Then link the object files and put the result in the 
            # package build directory.
            package = build_info.get('package', '')
            self.compiler.link_shared_lib(
                objects, lib_name,
                output_dir=os.path.join(self.build_clib, package),
                extra_postargs=build_info.get('extra_link_args', []),
                debug=self.debug,)


class custom_clean(clean):
    """Customized clean command

    Customized clean command removes .pyc files from the project, 
    as well as build and dist directories."""
    def run(self):
        log.info('running custom_clean')
        # Remove .pyc files
        if hasattr(os, 'walk'):
            for root, dirs, files in os.walk('.'):
                for f in files:
                    if f.endswith('.pyc'):
                        log.info("removing '%s'" % f)
                        try:
                            os.unlink(f)
                        except:
                            pass

        # Remove generated directories
        for dir in ['build', 'dist']:
            if os.path.exists(dir):
                log.info("removing '%s' (and everything under it)"%dir)
                try:
                    shutil.rmtree(dir, ignore_errors=True)
                except:
                    pass

        clean.run(self)

class custom_sdist(sdist):
    """Customized sdist command"""
    def run(self):
        log.info('running custom_sdist')
        sdist.run(self)

class BinaryDistribution(dist.Distribution):
    def is_pure(self):
        return False
    def has_ext_modules(self):
        return True

class custom_install(install):
    def finalize_options(self):
        install.finalize_options(self)
        self.install_lib = self.install_platlib

def main():
    # Just in case we are being called from a different directory
    cwd = os.path.dirname(__file__)
    if cwd:
        os.chdir(cwd)

    # Get the target platform
    system  = platform.system().lower()

    # Setup the extension module
    # Setup the library
    ext_modules = None
    libraries = None
    package_data = []
    if 'windows' in system:
        package_data = ['distorm3.dll']
    elif 'darwin' in system or 'macosx' in system:
        libraries = [(
            'distorm3', dict(
            package='distorm3',
            sources=get_sources,
            include_dirs=['src', 'include'],
            extra_compile_args=['-arch', 'i386', '-arch', 'x86_64', '-O2',
                                '-Wall', '-fPIC', '-DSUPPORT_64BIT_OFFSET',
                                '-DDISTORM_DYNAMIC']))]
    elif 'cygwin' in system:
        libraries = [(
            'distorm3', dict(
            package='distorm3',
            sources=get_sources,
            include_dirs=['src', 'include'],
            extra_compile_args=['-fPIC', '-O2', '-Wall',
                                '-DSUPPORT_64BIT_OFFSET',
                                '-DDISTORM_STATIC']))]
    else:
        libraries = [(
            'distorm3', dict(
            package='distorm3',
            sources=get_sources,
            include_dirs=['src', 'include'],
            extra_link_args=['-Wl,-soname,libdistorm3.so.3'],
            extra_compile_args=['-fPIC', '-O2', '-Wall',
                                '-DSUPPORT_64BIT_OFFSET',
                                '-DDISTORM_STATIC']))]

    options = {

    # Setup instructions
    'requires'          : ['ctypes'],
    'provides'          : ['distorm3'],
    'packages'          : ['distorm3'],
    'package_dir'       : { '' : 'python' },
    'cmdclass'          : { 'build' : custom_build,
                            'build_clib' : custom_build_clib,
                            'clean' : custom_clean, 
                            'sdist' : custom_sdist,
                            'install' : custom_install },
    'libraries'         : libraries,
    'package_data'      : {'distorm3': package_data},
    'distclass'         : BinaryDistribution,

    # Metadata
    'name'              : 'distorm3',
    'version'           : '3.4.1',
    'description'       : 'The goal of diStorm3 is to decode x86/AMD64' \
                          ' binary streams and return a structure that' \
                          ' describes each instruction.',
    'long_description'  : (
                        'Powerful Disassembler Library For AMD64\n'
                        'by Gil Dabah (distorm@gmail.com)\n'
                        '\n'
                        'Python bindings by Mario Vilas (mvilas@gmail.com)'
                        ),
    'author'            : 'Gil Dabah',
    'author_email'      : 'distorm@gmail.com',
    'maintainer'        : 'Gil Dabah',
    'maintainer_email'  : 'distorm@gmail.com',
    'url'               : 'https://github.com/gdabah/distorm/',
    'download_url'      : 'https://github.com/gdabah/distorm/',
    'platforms'         : ['cygwin', 'win', 'linux', 'macosx'],
    'classifiers'       : [
                        'License :: OSI Approved :: BSD License',
                        'Development Status :: 5 - Production/Stable',
                        'Intended Audience :: Developers',
                        'Natural Language :: English',
                        'Operating System :: Microsoft :: Windows',
                        'Operating System :: MacOS :: MacOS X',
                        'Operating System :: POSIX :: Linux',
                        'Programming Language :: Python :: 2.7',
                        'Programming Language :: Python :: 3.5',
                        'Topic :: Software Development :: Disassemblers',
                        'Topic :: Software Development :: Libraries :: Python Modules',
                        ]
    }

    # Call the setup function
    setup(**options)

if __name__ == '__main__':
    main()
