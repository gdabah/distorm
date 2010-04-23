#!/bin/bash

#
# instpython.sh, Install .so into Python2.6 Library
#

#
# Check for libdistorm3.so in given Directory
#

if [ ! -f libdistorm64.dylib ]; then
	echo "*** Error: Can't find libdistorm64.dylib!"
	exit 0
fi

#
# Copy it
#

cp libdistorm3.so /System/Library/Frameworks/Python.framework/Versions/Current/lib/python2.6/lib-dynload/distorm3.so 2> /dev/null

#
# Everything went well?
#

if [ $? == 1 ]; then
	echo "*** Error: Unable to copy libdistorm3.so to /System/Library/Frameworks/Python.framework/Versions/Current/lib/python2.6/lib-dynload, Permission denied?"
	exit 0
fi

#
# Done.
#

echo "* Done!"
exit 1
