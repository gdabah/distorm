Powerful Disassembler Library For x86/AMD64
-----------

Welcome to the diStorm3 binary stream disassembler library project.

diStorm3 is really a decomposer, which means it takes an instruction and returns a binary structure which describes it rather than static text, which is great for advanced binary code analysis.

diStorm3 is super lightweight (~45KB), ultra fast and easy to use (a single API), licensed under BSD!

For a light hooking library see the https://github.com/gdabah/distormx project.

"We benchmarked five popular open-source disassembly libraries and chose diStorm3, which had the best performance (and furthermore, has complete 64-bit support).", July 2014, Quoting David Williams-King in his Thesis about Binary Shuffling.

Installing diStorm3 -
'python -m pip install distorm3'

RTFM, the wiki has plenty of info.


# Installing distorm(vcpkg)

You can download and install distorm using the [vcpkg](https://github.com/Microsoft/vcpkg) dependency manager:

git clone https://github.com/Microsoft/vcpkg.git

cd vcpkg

./bootstrap-vcpkg.sh

./vcpkg integrate install

vcpkg install distorm


The distorm port in vcpkg is kept up to date by Microsoft team members and community contributors. If the version is out of date, please [create an issue or pull request](https://github.com/Microsoft/vcpkg) on the vcpkg repository.
