.. _everest_modules_handwritten_EvseV2G:

*******************************************
EvseV2G
*******************************************

:ref:`Link <everest_modules_EvseV2G>` to the module's reference.
This module includes a DIN70121 and ISO15118-2 implementation provided by chargebyte GmbH

Feature List
============

This document contains feature lists for DIN70121 and ISO15118-2 features, which EvseV2G supports.
These lists serve as a quick overview of which features are supported.

DIN70121
--------

===============  ==================
Feature          Supported
===============  ==================
DC               ✔️
ExternalPayment  ✔️
===============  ==================

ISO15118-2
----------

=======================  ==================
Feature                  Supported
=======================  ==================
AC                       ✔️
DC                       ✔️
TCP & TLS 1.2            ✔️
ExternalPayment          ✔️
Plug&Charge              ✔️
CertificateInstallation  ✔️
CertificateUpdate        
Pause/Resume             ✔️
Schedule Renegotation    
Smart Charging           
Internet Service         
=======================  ==================

Bundled libcbv2g
================

This module ships with the **libcbv2g** sources. Both the PlatformIO build
and the CMake module automatically compile the library so no manual setup
is required. When building via PlatformIO, the `extraScript` in
``library.json`` invokes ``pio-build_libcbv2g.py`` which configures and
builds libcbv2g for the ESP32 toolchain. The CMake build simply adds the
library with ``add_subdirectory(lib/libcbv2g)`` and links the
``cbv2g::`` targets.
