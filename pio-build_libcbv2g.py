Import("env")
import os, subprocess, shutil

# 1) Locate everything by PROJECT_DIR
PROJ_DIR = env["PROJECT_DIR"]
CBV2G    = os.path.join(PROJ_DIR, "lib", "libcbv2g")
BUILD    = os.path.join(PROJ_DIR, ".pio", "libcbv2g-" + env["PIOENV"])


# 2) Helper to find the ESP32-S3 cross-compiler

def find_xtensa_tool(name):
    tool = f"xtensa-esp32s3-elf-{name}"
    path = shutil.which(tool)
    return path or tool

CC     = find_xtensa_tool("gcc")
CXX    = find_xtensa_tool("g++")
AR     = find_xtensa_tool("ar")
RANLIB = find_xtensa_tool("ranlib")

# 3) Build libcbv2g only once

def ensure_build():
    if not os.path.exists(os.path.join(CBV2G, "CMakeLists.txt")):
        # Fetch submodule if it hasn't been initialized yet
        subprocess.check_call([
            "git", "submodule", "update", "--init", "--recursive"
        ], cwd=PROJ_DIR)
    if os.path.isfile(os.path.join(BUILD, "libcbv2g_exi_codec.a")):
        return

    os.makedirs(BUILD, exist_ok=True)
    cmake_cmd = [
        "cmake", "-S", CBV2G, "-B", BUILD, "-G", "Ninja",
        "-DCMAKE_SYSTEM_NAME=Generic",
        "-DCMAKE_BUILD_TYPE=MinSizeRel",
        f"-DCMAKE_C_COMPILER={CC}",
        f"-DCMAKE_CXX_COMPILER={CXX}",
        f"-DCMAKE_AR={AR}",
        f"-DCMAKE_RANLIB={RANLIB}",
        "-DCB_V2G_BUILD_TESTS=0",
        "-DCMAKE_C_FLAGS=-mlongcalls -ffunction-sections -fdata-sections",
        "-DCMAKE_CXX_FLAGS=-mlongcalls -ffunction-sections -fdata-sections"
    ]
    subprocess.check_call(cmake_cmd, cwd=PROJ_DIR)
    subprocess.check_call(["cmake", "--build", BUILD], cwd=PROJ_DIR)

ensure_build()

# 4) Inject into PIO build

env.Prepend(
    CPPPATH=[os.path.join(CBV2G, "include")],
    LIBPATH=[os.path.join(BUILD, "lib", "cbv2g")],
    LIBS=[
        "cbv2g_exi_codec",
        "cbv2g_tp",
        "cbv2g_iso2",
        "cbv2g_iso20",
        "cbv2g_din",
    ]
)
