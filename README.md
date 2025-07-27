# HLCV2G Library

This repository contains the HLCV2G module along with a bundled copy of
chargebyte's **libcbv2g**. The library can be built either with
[PlatformIO](https://platformio.org/) or using CMake.

## Building with PlatformIO

1. Install PlatformIO's CLI (`pip install platformio`).
2. Run `platformio run -t lib` in the repository root. PlatformIO will
   invoke `pio-build_libcbv2g.py` through `library.json` and build the
   static libraries under `.pio/`.

The `platformio.ini` file defines an environment for the `esp32-s3-devkitc-1`
board. You can also use `platformio ci` for automated builds:

```sh
platformio ci -c platformio.ini -l . -b esp32-s3-devkitc-1 -t lib
```

## Building with CMake

The library can also be built with the regular CMake toolchain. Create a
build directory and point CMake at the source tree:

```sh
cmake -S . -B build -GNinja
cmake --build build
```

The bundled libcbv2g sources are added automatically via
`add_subdirectory(lib/libcbv2g)` in `CMakeLists.txt`.
