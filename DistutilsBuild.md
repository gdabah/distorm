When using 'python setup.py build' you might get some trouble.
Maybe this log can help you:

```
C:\Users\arkon\Desktop\distorm3-1.0>python setup.py build
running build
running custom_build
running build_py
copying python\distorm3\sample.py -> build\lib\distorm3
copying python\distorm3\__init__.py -> build\lib\distorm3
running build_clib
running custom_build_clib
building 'distorm3' library
error: Unable to find vcvarsall.bat
```

Try again, verbose this time.

```
C:\Users\arkon\Desktop\distorm3-1.0>python setup.py --verbose build
running build
running custom_build
running build_py
copying python\distorm3\sample.py -> build\lib\distorm3
copying python\distorm3\__init__.py -> build\lib\distorm3
running build_clib
running custom_build_clib
Importing new compiler from distutils.msvc9compiler
building 'distorm3' library
Unable to find productdir in registry
Env var VS90COMNTOOLS is not set or invalid
No productdir found
error: Unable to find vcvarsall.bat
```

Ok, now we know what the problem is. Assuming we got Visual Studio installed, we will get its Common Tool envier.
```
C:\Users\arkon\Desktop\distorm3-1.0>set vs
VS100COMNTOOLS=C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\Tools\
```
Now create a duplicate of the original one with a new one that distutils looks for!
```
C:\Users\arkon\Desktop\distorm3-1.0>set VS90COMNTOOLS=C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\Tools\
```
And here we go again:
```
C:\Users\arkon\Desktop\distorm3-1.0>python setup.py --verbose build
running build
running custom_build
running build_py
copying python\distorm3\sample.py -> build\lib\distorm3
copying python\distorm3\__init__.py -> build\lib\distorm3
running build_clib
running custom_build_clib
Importing new compiler from distutils.msvc9compiler
...
```