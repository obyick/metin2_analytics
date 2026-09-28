import ctypes
import ctypes.wintypes as wt

import psutil


START = 0x836CC000
END = 0x836CD200

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

READABLE = {
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
}


kernel32 = ctypes.WinDLL(
    "kernel32",
    use_last_error=True,
)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


kernel32.OpenProcess.argtypes = [
    wt.DWORD,
    wt.BOOL,
    wt.DWORD,
]

kernel32.OpenProcess.restype = wt.HANDLE


kernel32.VirtualQueryEx.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]

kernel32.VirtualQueryEx.restype = ctypes.c_size_t


kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

kernel32.ReadProcessMemory.restype = wt.BOOL


kernel32.CloseHandle.argtypes = [
    wt.HANDLE,
]

kernel32.CloseHandle.restype = wt.BOOL


def find_pids():
    pids = []

    for process in psutil.process_iter(
        ["pid", "name"]
    ):
        try:
            name = process.info["name"]

            if (
                name
                and name.lower()
                == "metin2client.exe"
            ):
                pids.append(process.info["pid"])

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):
            continue

    return pids


def open_process(pid):
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION
        | PROCESS_VM_READ,
        False,
        pid,
    )

    if not handle:
        raise ctypes.WinError(
            ctypes.get_last_error()
        )

    return handle


def query_region(handle, address):
    mbi = MEMORY_BASIC_INFORMATION()

    result = kernel32.VirtualQueryEx(
        handle,
        ctypes.c_void_p(address),
        ctypes.byref(mbi),
        ctypes.sizeof(mbi),
    )

    if result == 0:
        return None

    return mbi


def region_is_readable(mbi, address, size):
    if mbi is None:
        return False

    base = int(mbi.BaseAddress or 0)
    region_size = int(mbi.RegionSize)

    if mbi.State != MEM_COMMIT:
        return False

    if mbi.Protect not in READABLE:
        return False

    region_end = base + region_size
    requested_end = address + size

    return (
        address >= base
        and requested_end <= region_end
    )


def select_process():
    pids = find_pids()

    if not pids:
        raise RuntimeError(
            "metin2client.exe não foi encontrado."
        )

    print(
        f"Clientes encontrados: {len(pids)}"
    )

    print()

    candidates = []

    for pid in pids:

        print(
            f"PID {pid}: verificando "
            f"0x{START:08X}..."
        )

        try:
            handle = open_process(pid)

        except OSError as error:
            print(
                f"  OpenProcess falhou: "
                f"{error}"
            )
            continue

        try:
            mbi = query_region(
                handle,
                START,
            )

            if mbi is None:
                print(
                    "  VirtualQueryEx falhou."
                )
                continue

            base = int(
                mbi.BaseAddress or 0
            )

            size = int(
                mbi.RegionSize
            )

            protect = int(
                mbi.Protect
            )

            state = int(
                mbi.State
            )

            print(
                f"  região: "
                f"0x{base:08X} - "
                f"0x{base + size:08X}"
            )

            print(
                f"  tamanho: "
                f"0x{size:X}"
            )

            print(
                f"  state: "
                f"0x{state:X}"
            )

            print(
                f"  protect: "
                f"0x{protect:X}"
            )

            readable = region_is_readable(
                mbi,
                START,
                END - START,
            )

            print(
                f"  intervalo solicitado: "
                f"{'LEGÍVEL' if readable else 'NÃO LEGÍVEL'}"
            )

            if readable:
                candidates.append(
                    (
                        pid,
                        handle,
                    )
                )

            else:
                kernel32.CloseHandle(handle)

        except Exception:
            kernel32.CloseHandle(handle)
            raise

        print()

    if not candidates:
        raise RuntimeError(
            "Nenhum metin2client.exe possui "
            "a região solicitada legível."
        )

    if len(candidates) > 1:
        print(
            "Mais de um cliente possui "
            "a região legível."
        )

        print(
            f"Usando PID {candidates[0][0]}."
        )

        for _, handle in candidates[1:]:
            kernel32.CloseHandle(handle)

        return candidates[0]

    return candidates[0]


def read_memory(handle):
    size = END - START

    buffer = ctypes.create_string_buffer(
        size
    )

    read = ctypes.c_size_t()

    success = kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(START),
        buffer,
        size,
        ctypes.byref(read),
    )

    bytes_read = read.value

    if not success and bytes_read == 0:
        raise ctypes.WinError(
            ctypes.get_last_error()
        )

    if bytes_read < size:
        print(
            f"Aviso: leitura parcial: "
            f"{bytes_read}/{size} bytes."
        )

    return buffer.raw[:bytes_read]


def u32(data, offset):
    return int.from_bytes(
        data[offset:offset + 4],
        "little",
        signed=False,
    )


def main():
    pid, handle = select_process()

    try:
        print()
        print(
            f"Processo selecionado: "
            f"metin2client.exe"
        )

        print(
            f"PID: {pid}"
        )

        print()

        data = read_memory(handle)

        print(
            f"Região lida: "
            f"0x{START:08X} - "
            f"0x{START + len(data):08X}"
        )

        print()
        print(
            "=== SLOTS 0-89 ==="
        )

        for slot in range(90):

            found = []

            target = slot.to_bytes(
                4,
                "little",
            )

            for offset in range(
                0,
                len(data) - 4,
                4,
            ):
                if (
                    data[offset:offset + 4]
                    != target
                ):
                    continue

                address = START + offset

                before = [
                    u32(
                        data,
                        offset - i * 4,
                    )
                    for i in range(1, 5)
                    if offset >= i * 4
                ]

                after = [
                    u32(
                        data,
                        offset + i * 4,
                    )
                    for i in range(1, 5)
                    if (
                        offset + i * 4 + 4
                        <= len(data)
                    )
                ]

                found.append(
                    (
                        address,
                        before,
                        after,
                    )
                )

            if not found:
                print(
                    f"slot {slot:2d}: "
                    f"NÃO ENCONTRADO"
                )
                continue

            print(
                f"slot {slot:2d}: "
                f"{len(found)} ocorrência(s)"
            )

            for (
                address,
                before,
                after,
            ) in found:

                print(
                    f"  0x{address:08X}"
                )

                print(
                    "    antes:",
                    " ".join(
                        f"{value:08X}"
                        for value in reversed(before)
                    ),
                )

                print(
                    "    depois:",
                    " ".join(
                        f"{value:08X}"
                        for value in after
                    ),
                )

    finally:
        kernel32.CloseHandle(handle)


if __name__ == "__main__":
    main()