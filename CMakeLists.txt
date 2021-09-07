cmake_minimum_required(VERSION 3.10)

#Version number should be updated here before all releases
project(distorm VERSION 3.5.2 LANGUAGES C)

#Both src and include have headers files
include_directories(include)
include_directories(src)

#Removing the default suffix (.so / .dll) from the shared library naming scheme
set(CMAKE_SHARED_LIBRARY_SUFFIX "")
#Removing default prefix (lib) from the static library naming scheme
set(CMAKE_STATIC_LIBRARY_PREFIX "")

#Set platform specific options
if(${CMAKE_HOST_SYSTEM_NAME} MATCHES Linux)
    set(LINUX TRUE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -O2 -Wall -std=c99")
    set(TARGET_BASE distorm3.so)
    set(SHARED_LIB_NAME ${TARGET_BASE}.${PROJECT_VERSION})
    set(STATIC_LIB_NAME distorm3)
    set(SYMLINK_FILENAME libdistorm3.so)
endif()

if(${CMAKE_HOST_SYSTEM_NAME} MATCHES Darwin)
    set(MACOSX TRUE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -arch x86_64 -O2 -Wall -fPIC")
    set(TARGET_BASE distorm3.so)
    set(SHARED_LIB_NAME ${TARGET_BASE}.${PROJECT_VERSION}.dylib)
    set(STATIC_LIB_NAME distorm3)
    set(SYMLINK_FILENAME libdistorm3.dylib)
endif()

if(${CMAKE_HOST_SYSTEM_NAME} MATCHES Windows)
    set(WINDOWS TRUE)
    set(SHARED_LIB_NAME libdistorm3.dll)
    set(STATIC_LIB_NAME distorm3)
endif()

#Check if machine is 64-bit
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ENV{SUPPORT_64BIT_OFFSET} 1)
endif()

#List all source files to tell Makefile what to compile
set(SOURCE_FILES 
    src/decoder.c
    src/decoder.h
    src/distorm.c
    include/distorm.h
    src/instructions.c
    src/instructions.h
    src/insts.c
    src/insts.h
    src/mnemonics.c
    include/mnemonics.h
    src/operands.c
    src/operands.h
    src/prefix.c
    src/prefix.h
    src/textdefs.c
    src/textdefs.h
)

#Build both dynamic and static libraries
add_library(${SHARED_LIB_NAME} SHARED ${SOURCE_FILES})
add_library(${STATIC_LIB_NAME} STATIC ${SOURCE_FILES})

#Add symlink if we are on Linux or Mac for convention
if(LINUX OR MACOSX)
    ADD_CUSTOM_TARGET(link_target ALL COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SHARED_LIBRARY_PREFIX}${SHARED_LIB_NAME} ${SYMLINK_FILENAME})
endif()

#The SOURCE_PACKAGE_ARCH will help us when creating our releases for multiple platforms
if(NOT DEFINED SOURCE_PACKAGE_ARCH)
    set(SOURCE_PACKAGE_ARCH ${CMAKE_HOST_SYSTEM_NAME})
endif()

#These files do not belong in the source code release
set(IGNORED_SOURCE_FILES
    \\\\.git
    _CPack_Packages
    CMakeFiles
    Makefile
    libdistorm3
    \\\\.a
    \\\\.dylib
    \\\\.lib
    CPackConfig\\\\.cmake
    CPackSourceConfig\\\\.cmake
    CMakeCache\\\\.txt
    cmake_install\\\\.cmake
    \\\\.zip
    \\\\.tar\\\\.gz
    scripts
    __pycache__
)

#Add an install location for Linux and Mac
#Also ignore the windows directory
if(${SOURCE_PACKAGE_ARCH} MATCHES Linux OR ${SOURCE_PACKAGE_ARCH} MATCHES Darwin)
    install(TARGETS ${SHARED_LIB_NAME} DESTINATION /usr/local/lib)
    install(FILES ${SYMLINK_FILENAME} DESTINATION /usr/local/lib)
    set(CPACK_SOURCE_IGNORE_FILES windows ${IGNORED_SOURCE_FILES})
else()
    set(CPACK_SOURCE_IGNORE_FILES ${IGNORED_SOURCE_FILES})
endif()

#Generate a .zip and .tar.gz source release for each platform
set(CPACK_SOURCE_GENERATOR ZIP TGZ)
#Name the source release
set(CPACK_SOURCE_PACKAGE_FILE_NAME distorm-${PROJECT_VERSION}-${SOURCE_PACKAGE_ARCH})

include(CPack)