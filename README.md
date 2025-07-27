# HLCV2G Library

HLCV2G provides the ISO 15118/DIN70121 charger communication used by the EVSE component in EVerest. It now bundles [libcbv2g](https://github.com/EVerest/libcbv2g) directly so no separate setup is required.

## Building

The library is built using CMake inside the EVerest build system. The bundled libcbv2g sources are compiled as part of the module build. For PlatformIO projects the `pio-build_libcbv2g.py` script performs the same integration automatically.

