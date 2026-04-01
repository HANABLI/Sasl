# Sasl

This is the implementation of the Sasl (Simple Authentication security layer) protocol and its mechanisms
as defined in the [RFC4422](https://datatracker.ietf.org/doc/html/rfc4422)

## Usage

`Sasl::Login` class implements the draft murchison SASL LOGIN mechanism.<br/>
`Sasl::Plain` class implements the PLAIN SASL mechanism.<br/>
`Sasl::Scram` class implements the Salted Challenge Response Authentication Mechanism.<br/>

## Building the C++ Implementation

A portable library is built which depends on the C++11 compiler, the C++
standard library, and non-standard dependencies listed below. It should be
supported on almost any platform. The following are recommended toolchains for
popular platforms.

- Windows -- [Visual Studio](https://www.visualstudio.com/) (Microsoft Visual
  C++)
- Linux -- clang or gcc
- MacOS -- Xcode (clang)

This library is not intended to stand alone. It is intended to be included in
a larger solution which uses [CMake](https://cmake.org/) to generate the build
system and build applications which will link with the library.

There are two distinct steps in the build process:

1. Generation of the build system, using CMake
2. Compiling, linking, etc., using CMake-compatible toolchain

### Prerequisites

- [CMake](https://cmake.org/) version 3.20 or newer
- C++17 toolchain compatible with CMake for your development platform (e.g.
  [Visual Studio](https://www.visualstudio.com/) on Windows)

### Build system generation

Generate the build system using [CMake](https://cmake.org/) from the solution
root. For example:

```bash
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A "x64" ..
```

### Compiling, linking, et cetera

Either use [CMake](https://cmake.org/) or your toolchain's IDE to build.
For [CMake](https://cmake.org/):

```bash
cd build
cmake --build . --config Release
```
