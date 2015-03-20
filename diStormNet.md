diStorm for C# supports only x64 and therefore should be compiled for x64 with unsafe code.

The project assumes that the directories hierarchy is just the same as in the software distribution.

Steps to follow:
1. First compile diStorm library as a DLL for x64 target.
2. Now open the C# solution, and execute the opcodes.tt file (inside the IDE) which is a script to generate a recent mnemonics table from mnemonics.h into the C# project, usually it will already be up to date from the sources. You can run it anyway to be on the safe side.
3. Before proceeding, make sure your targets are all x64.
4. The tester project has a build event to copy distorm3.dll into its target directory.
5. Now run it all, good luck :)

If you experience any problems please issue a ticket so I could solve it.