The Java wrapper of diStorm3 is now part of the package, and you can find it under examples\java.

Please follow the next instruction in order to get it to work:

  1. Compile the diStorm library in Visual Studio, clib for x64.
  1. Open up examples\java\jdistorm solution in Visual Studio.
  1. Fix the existing Java paths in the configuration properties:
    * Include Paths: Project -> jdistorm properties -> C++ -> General -> Additional Include Directories
    * Library Paths: Project -> jdistorm properties -> Linker -> General -> Additional Include Directories
  1. Compile jdistorm for x64.
  1. Copy the output jdistorm.dll into examples\java\distorm.
  1. Open Eclipse.
  1. File -> Import -> General -> Existing Projects into Workspace and choose the '.project' file of the Java distorm project.
  1. Find the main.java file, and hit 'run', you should see the demo calls to Decode and Decompose.