import ctypes
import ctypes.wintypes as wt
import json
import os
import psutil

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

KNOWN_MAPS = {
    b"metin2_map_c1": "Pyungmoo",
    b"metin2_map_c3": "Bakra",
    b"map_n_threeway": "Vale Seungryong",
}

CHUNK_SIZE = 1024 * 1024
OVERLAP = 32

CACHE_FILE = os.path.join(
    os.path.dirname(__file__),
    "map_address.json",
)


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


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
OpenProcess.restype = wt.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wt.HANDLE,
    wt.LPCVOID,
    wt.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
ReadProcessMemory.restype = wt.BOOL

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    wt.HANDLE,
    wt.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
VirtualQueryEx.restype = ctypes.c_size_t

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wt.HANDLE]
CloseHandle.restype = wt.BOOL


def pid():
    for process in psutil.process_iter(["pid", "name"]):
        name = process.info["name"]

        if name and name.lower() == "metin2client.exe":
            print(
                f"Found process: {name} "
                f"(PID: {process.info['pid']})"
            )
            return process.info["pid"]

    return None


def read_bytes(handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()

    ok = ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(read),
    )

    if not ok or not read.value:
        return None

    return buffer.raw[:read.value]


def find_map_occurrences(handle):
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    occurrences = {}

    while True:
        result = VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )

        if not result:
            break

        base = int(mbi.BaseAddress or address)
        size = int(mbi.RegionSize)

        if size <= 0:
            break

        if (
            mbi.State == MEM_COMMIT
            and not (mbi.Protect & PAGE_NOACCESS)
            and not (mbi.Protect & PAGE_GUARD)
        ):
            offset = 0
            previous_tail = b""

            while offset < size:
                amount = min(
                    CHUNK_SIZE,
                    size - offset,
                )

                data = read_bytes(
                    handle,
                    base + offset,
                    amount,
                )

                if data:
                    combined = previous_tail + data
                    combined_base = (
                        base
                        + offset
                        - len(previous_tail)
                    )

                    for raw_name, display_name in KNOWN_MAPS.items():
                        search_from = 0

                        while True:
                            found = combined.find(
                                raw_name,
                                search_from,
                            )

                            if found == -1:
                                break

                            occurrences[
                                combined_base + found
                            ] = display_name

                            search_from = found + 1

                    previous_tail = combined[-OVERLAP:]

                offset += amount

        next_address = base + size

        if next_address <= address:
            break

        address = next_address

    return occurrences


def load_cache():
    if not os.path.exists(CACHE_FILE):
        return None

    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return None


def save_baseline(process_id, occurrences):
    data = {
        "pid": process_id,
        "occurrences": {
            str(address): name
            for address, name in occurrences.items()
        },
    }

    with open(CACHE_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def discover_map_address(process_id):
    handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        process_id,
    )

    if not handle:
        return None

    try:
        print(f"Escaneando PID {process_id}...")

        occurrences = find_map_occurrences(handle)

        if not occurrences:
            print("Nenhuma ocorrência de mapa encontrada.")
            return None

        save_baseline(
            process_id,
            occurrences,
        )

        print(
            f"{len(occurrences)} ocorrências encontradas."
        )
        print()
        print("Baseline salvo.")
        print("Mude de mapa no jogo.")
        print("Execute o script novamente.")

        return None

    finally:
        CloseHandle(handle)


def detect_map_address(process_id, cache):
    if int(cache.get("pid", -1)) != process_id:
        print("O cache pertence a outro PID.")
        print("Iniciando nova descoberta...")
        return discover_map_address(process_id)

    handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        process_id,
    )

    if not handle:
        return None

    try:
        changed = []

        occurrences = cache.get("occurrences", {})

        for address_text, old_name in occurrences.items():
            address = int(address_text)

            data = read_bytes(
                handle,
                address,
                32,
            )

            if not data:
                continue

            new_name = None

            for raw_name, display_name in KNOWN_MAPS.items():
                if data.startswith(raw_name):
                    new_name = display_name
                    break

            if new_name and new_name != old_name:
                changed.append(
                    (
                        address,
                        old_name,
                        new_name,
                    )
                )

        if len(changed) != 1:
            if not changed:
                print(
                    "Nenhuma ocorrência dinâmica mudou."
                )
            else:
                print(
                    f"{len(changed)} ocorrências mudaram."
                )

            return None

        address, old_name, new_name = changed[0]

        with open(CACHE_FILE, "w", encoding="utf-8") as file:
            json.dump(
                {
                    "pid": process_id,
                    "address": address,
                    "map": new_name,
                },
                file,
                indent=2,
            )

        print(
            f"Endereço encontrado: 0x{address:X}"
        )
        print(
            f"Mapa: {old_name} -> {new_name}"
        )

        return new_name

    finally:
        CloseHandle(handle)


def mapa():
    process_id = pid()

    if not process_id:
        return None

    cache = load_cache()

    if (
        cache
        and int(cache.get("pid", -1)) == process_id
        and "address" in cache
    ):
        handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            process_id,
        )

        if not handle:
            return None

        try:
            address = int(cache["address"])

            data = read_bytes(
                handle,
                address,
                32,
            )

            if data:
                for raw_name, display_name in KNOWN_MAPS.items():
                    if data.startswith(raw_name):
                        return display_name

        finally:
            CloseHandle(handle)

        return None

    if cache:
        return detect_map_address(
            process_id,
            cache,
        )

    return discover_map_address(
        process_id
    )


if __name__ == "__main__":
    print(mapa())