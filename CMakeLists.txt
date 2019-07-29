#
# Cmake Configuration
#

# Need 3.9 to support CXX_STANDARD=17 
CMAKE_MINIMUM_REQUIRED(VERSION 3.9.0)


PROJECT(ehp)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

option(USE_ELFIO "Use the elfio library to parse elf files" OFF)
if(USE_ELFIO)
   add_definitions(-DUSE_ELFIO)
endif()

# Use C++17
set(CMAKE_CXX_STANDARD 17)
# Error if it's not available
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Base include path for ehp
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_compile_options(-Werror)
add_compile_options(-fPIC)
add_subdirectory(src)

# ---------------------------------------------------------------------------
# Export config for use by other CMake projects
# ---------------------------------------------------------------------------
export(TARGETS ehp FILE "${CMAKE_CURRENT_BINARY_DIR}/ehpTargets.cmake")
file(
  WRITE "${CMAKE_CURRENT_BINARY_DIR}/ehpConfig.cmake"
        "
            include(\"\$\{CMAKE_CURRENT_LIST_DIR\}/ehpTargets.cmake\")
            set_property(
                TARGET ehp
                APPEND PROPERTY
                    INTERFACE_INCLUDE_DIRECTORIES \"${CMAKE_BINARY_DIR}/include\"
            )
        "
    )
export(PACKAGE ehp)