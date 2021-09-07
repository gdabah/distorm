#If we are in the scripts directory, change to the main directory
if [[ "$PWD" == *"scripts"* ]]; then
    cd ..
fi

current_files=$(ls)

#If CMakeLists is not in the current directory, exit with error
if ! [[ "$current_files" == *"CMakeLists.txt"* ]]; then
    echo "Could not find CMakeLists.txt in current directory. Run this script from either the main directory or the scripts directory"
    exit 1
fi

#Create Linux source release
cmake -DSOURCE_PACKAGE_ARCH=Linux .
make package_source

#Create Mac source release
cmake -DSOURCE_PACKAGE_ARCH=Darwin .
make package_source

#Create Windows source release
cmake -DSOURCE_PACKAGE_ARCH=Windows .
make package_source