#!/bin/bash

#
# instpython.sh, Install .so into Python2.3 Library
#

#
# Check for libdistorm64.so in given Directory
#

if [ ! -f libdistorm64.dylib ]; then
	echo "*** Error: Can't find libdistorm64.dylib!"
	exit 0
fi

#
# Copy it
#

cp libdistorm64.so /System/Library/Frameworks/Python.framework/Versions/Current/lib/python2.5/lib-dynload/distorm.so 2> /dev/null

#
# Everything went well?
#

if [ $? == 1 ]; then
	echo "*** Error: Unable to copy libdistorm64.so to /System/Library/Frameworks/Python.framework/Versions/Current/lib/python2.5/lib-dynload, Permission denied?"
	exit 0
fi

#
# Done.
#

echo "* Done!"
exit 1
