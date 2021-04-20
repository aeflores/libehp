This is a library to parse ELF's exception handling information out of its binary form and into it's "parse tree" form.

The API is documented in the include directory.  The source tree is complicated and understanding it should not be necessary.

The test directory contains a simple example of how to use the API.

Notes:

1. Compilation requires C++11 or later.
1. Additional documentation will be provided in later versions 
1. API is incomplete and untested in some areas.  Future versions will improve stability.
1. Use `git clone --recursive` to pull down required submodules


# Building
## Building with Scons

Build with `scons`.

1. Add `debug=1` for debug build.
1. Add '--no_elfio' to compile without the third party libraries

## Build with Cmake

To compile with cmake type:

```
cmake . -Bbuild
cd build
cmake --build .
```

In contrast to scons, the default compilation in cmake is **without** the elfio library. If you want to compile with elfio
use the following commands:

```
cmake . -Bbuild  -DUSE_ELFIO=ON
cd build
cmake --build .
```


# Known Uses:

LibEHP is used in [Grammatech's Datalog Diassembler projects](https://github.com/GrammaTech/ddisasm)
