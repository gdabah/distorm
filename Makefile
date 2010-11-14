PYTHON=C:\Python26\python.exe

all:
	@echo type "make src" to build a source distro
	@echo type "make win" to build installers for Windows

clean:
	$(PYTHON) setup.py clean

src: clean
	$(PYTHON) setup.py sdist

win26: clean
	$(PYTHON) setup.py bdist_msi --target-version=2.6

win25: clean
	$(PYTHON) setup.py bdist_msi --target-version=2.5

win24: clean
	$(PYTHON) setup.py bdist_msi --target-version=2.4

win: win24 win25 win26 clean
	$(PYTHON) setup.py bdist_wininst
