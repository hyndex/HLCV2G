# HLCV2G Library

This repository provides the HLCV2G module used by the [EVerest](https://github.com/EVerest/everest) project. The module bundles chargebyte's **libcbv2g** to implement DIN70121 and ISO15118-2 high level communication with electric vehicles.

The sources can be built either with [PlatformIO](https://platformio.org/) or a regular CMake toolchain. The `lib/` directory already contains libcbv2g and is compiled automatically by both build systems.

## Building with PlatformIO

1. Install PlatformIO's CLI (`pip install platformio`).
2. Run `platformio run -t lib` in the repository root. `library.json` invokes `pio-build_libcbv2g.py` to compile libcbv2g and places the resulting libraries under `.pio/`.

The `platformio.ini` file defines an environment for the `esp32-s3-devkitc-1` board. CI builds can be executed with:

```sh
platformio ci -c platformio.ini -l . -b esp32-s3-devkitc-1 -t lib
```

## Building with CMake

```sh
cmake -S . -B build -GNinja
cmake --build build
```

libcbv2g is added through `add_subdirectory(lib/libcbv2g)`.

## Supported Features

According to `doc.rst` the following features are available:

### DIN70121

- DC
- ExternalPayment

### ISO15118-2

- AC
- DC
- TCP & TLS 1.2
- ExternalPayment
- Plug&Charge
- CertificateInstallation
- Pause/Resume

`CertificateUpdate`, schedule renegotiation, smart charging and internet service are not implemented yet.

## Documentation

Further details and module usage can be found in the [EVerest documentation](https://everest.github.io/).
