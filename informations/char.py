import ctypes
import ctypes.wintypes as wt
import json
import os
import psutil
import struct


CHARACTERS = (
    "Irstag",
    "Mrakhurn",
    "Aaryin",
    "Ashoten",
    "Brasrag",
    "Irstae",
    "Irstaq",
)

CACHE = os.path.join(
    os.path.dirname(__file__),
    "char.cache",
)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wt.WORD),
        ("wReserved", wt.WORD),
        ("dwPageSize", wt.DWORD),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", wt.DWORD),
        ("dwProcessorType", wt.DWORD),
        ("dwAllocationGranularity", wt.DWORD),
        ("wProcessorLevel", wt.WORD),
        ("wProcessorRevision", wt.WORD),
    ]


kernel32 = ctypes.WinDLL(
    "kernel32",
    use_last_error=True,
)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [
    wt.DWORD,
    wt.BOOL,
    wt.DWORD,
]
OpenProcess.restype = wt.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
ReadProcessMemory.restype = ctypes.c_bool

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
]
VirtualQueryEx.restype = ctypes.c_size_t

CloseHandle = kernel32.CloseHandle

kernel32.GetSystemInfo.argtypes = [
    ctypes.POINTER(SYSTEM_INFO)
]


def find_pid():
    for p in psutil.process_iter(["pid", "name"]):
        try:
            if (
                p.info["name"]
                and p.info["name"].lower() == "metin2client.exe"
            ):
                return p.info["pid"]
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):
            pass

    return None


def read(handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    count = ctypes.c_size_t()

    if not ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(count),
    ):
        return None

    return buffer.raw[:count.value]


def validate(handle, address):
    data = read(handle, address, 0xA4)

    if not data or len(data) < 0xA4:
        return None

    for name in CHARACTERS:
        pattern = name.encode("ascii")

        if data.startswith(pattern):
            level = struct.unpack_from(
                "<I",
                data,
                0xA0,
            )[0]

            if 1 <= level <= 120:
                return name, level

    return None


def load_cache(pid):
    try:
        with open(CACHE, "r", encoding="utf-8") as file:
            cache = json.load(file)

        if cache.get("pid") == pid:
            return int(cache["address"])

    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ):
        pass

    return None


def save_cache(pid, address):
    with open(CACHE, "w", encoding="utf-8") as file:
        json.dump(
            {
                "pid": pid,
                "address": address,
            },
            file,
        )


def scan(handle):
    si = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(si))

    address = int(si.lpMinimumApplicationAddress)
    maximum = int(si.lpMaximumApplicationAddress)
    mbi = MEMORY_BASIC_INFORMATION()

    while address < maximum:
        if not VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        ):
            break

        base = int(mbi.BaseAddress)
        size = int(mbi.RegionSize)

        if (
            mbi.State == MEM_COMMIT
            and not mbi.Protect & PAGE_NOACCESS
            and not mbi.Protect & PAGE_GUARD
        ):
            for offset in range(0, size, 1024 * 1024):
                amount = min(
                    1024 * 1024,
                    size - offset,
                )

                data = read(
                    handle,
                    base + offset,
                    amount,
                )

                if not data:
                    continue

                for name in CHARACTERS:
                    pattern = name.encode("ascii")
                    pos = data.find(pattern)

                    while pos != -1:
                        candidate = base + offset + pos
                        result = validate(
                            handle,
                            candidate,
                        )

                        if result:
                            return candidate, result

                        pos = data.find(
                            pattern,
                            pos + 1,
                        )

        address = base + size

    return None


def personagem():
    pid = find_pid()

    if not pid:
        return None

    handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid,
    )

    if not handle:
        return None

    try:
        address = load_cache(pid)

        if address is not None:
            result = validate(
                handle,
                address,
            )

            if result:
                return result

        found = scan(handle)

        if not found:
            return None

        address, result = found
        save_cache(pid, address)

        return result

    finally:
        CloseHandle(handle)


if __name__ == "__main__":
    resultado = personagem()

    if resultado:
        print(*resultado, sep="\n")
    else:
        print("Personagem não encontrado.")