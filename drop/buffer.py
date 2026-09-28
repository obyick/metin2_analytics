import ctypes
import ctypes.wintypes as wintypes
import hashlib
import time
from datetime import datetime

import psutil


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100

READABLE = {
    0x02,
    0x04,
    0x08,
    0x20,
    0x40,
    0x80,
}

LOOT_PREFIX = b"Recebeste "
CHUNK_SIZE = 1024 * 1024

CLUSTER_DISTANCE = 8192
MIN_MESSAGES = 3
PADDING = 256

SCAN_INTERVAL = 0.05


kernel32 = ctypes.WinDLL(
    "kernel32",
    use_last_error=True,
)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [
    wintypes.HANDLE,
]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL


def find_pid():
    for process in psutil.process_iter(
        ["pid", "name"]
    ):
        try:
            if (
                process.info["name"]
                and process.info["name"].lower()
                == "metin2client.exe"
            ):
                if process.pid == 8524:
                    return process.pid
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):
            pass

    return None


def open_process(pid):
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION
        | PROCESS_VM_READ,
        False,
        pid,
    )

    if not handle:
        raise OSError(
            ctypes.get_last_error()
        )

    return handle


def get_regions(handle):
    result = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    size = ctypes.sizeof(mbi)

    while True:
        ok = kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            size,
        )

        if not ok:
            break

        base = int(mbi.BaseAddress or 0)
        region_size = int(mbi.RegionSize)
        protect = int(mbi.Protect)

        if (
            region_size
            and int(mbi.State) == MEM_COMMIT
            and (protect & 0xFF) in READABLE
            and not (protect & PAGE_GUARD)
        ):
            result.append(
                (base, region_size)
            )

        next_address = base + region_size

        if next_address <= address:
            break

        address = next_address

        if address >= 0x7FFFFFFFFFFF:
            break

    return result


def read_memory(handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()

    ok = kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(read),
    )

    if not ok or not read.value:
        return b""

    return buffer.raw[:read.value]


def extract_messages(data, base):
    messages = []
    position = 0

    while True:
        position = data.find(
            LOOT_PREFIX,
            position,
        )

        if position < 0:
            break

        end = data.find(
            b"\x00",
            position,
        )

        if end < 0:
            break

        raw = data[position:end]

        try:
            text = raw.decode(
                "cp1252",
                errors="strict",
            ).strip()
        except UnicodeDecodeError:
            text = ""

        if (
            text.startswith("Recebeste ")
            and len(text) <= 100
        ):
            messages.append(
                text
            )

        position += len(LOOT_PREFIX)

    return messages


def scan_region(handle, start, size):
    data = read_memory(
        handle,
        start,
        size,
    )

    if not data:
        return None

    digest = hashlib.blake2b(
        data,
        digest_size=8,
    ).digest()

    messages = extract_messages(
        data,
        start,
    )

    return digest, data, messages


def build_candidates(handle):
    all_messages = []

    for base, size in get_regions(handle):
        offset = 0

        while offset < size:
            amount = min(
                CHUNK_SIZE,
                size - offset,
            )

            data = read_memory(
                handle,
                base + offset,
                amount,
            )

            if data:
                position = 0

                while True:
                    position = data.find(
                        LOOT_PREFIX,
                        position,
                    )

                    if position < 0:
                        break

                    end = data.find(
                        b"\x00",
                        position,
                    )

                    if end >= 0:
                        try:
                            text = data[
                                position:end
                            ].decode(
                                "cp1252",
                                errors="strict",
                            ).strip()

                            if (
                                text.startswith(
                                    "Recebeste "
                                )
                                and len(text) <= 100
                            ):
                                all_messages.append(
                                    (
                                        base
                                        + offset
                                        + position,
                                        text,
                                    )
                                )
                        except UnicodeDecodeError:
                            pass

                    position += len(LOOT_PREFIX)

            offset += len(data) or amount

            if len(data) < amount:
                break

    all_messages.sort(
        key=lambda item: item[0]
    )

    clusters = []

    for address, text in all_messages:
        if not clusters:
            clusters.append(
                [(address, text)]
            )
            continue

        if (
            address
            - clusters[-1][-1][0]
            <= CLUSTER_DISTANCE
        ):
            clusters[-1].append(
                (address, text)
            )
        else:
            clusters.append(
                [(address, text)]
            )

    ranges = []

    for cluster in clusters:
        if len(cluster) < MIN_MESSAGES:
            continue

        start = max(
            0,
            cluster[0][0] - PADDING,
        )

        end = (
            cluster[-1][0]
            + PADDING
        )

        ranges.append(
            (start, end - start)
        )

    return ranges


def format_messages(messages):
    if not messages:
        return "(nenhuma mensagem)"

    unique = []

    for message in messages:
        if message not in unique:
            unique.append(message)

    return " | ".join(unique[:12])


def main():
    print("=" * 80)
    print("       METIN2 - LOOT BUFFER PROBE")
    print("=" * 80)
    print()
    print(
        "Monitora mudanças físicas nos candidatos "
        "de buffer do PID 8524."
    )
    print(
        "Nenhum filtro de ordem será aplicado."
    )
    print()
    print(
        "Faça alguns drops no personagem 8524."
    )
    print(
        "Ctrl+C para encerrar."
    )
    print()

    pid = find_pid()

    if pid is None:
        print(
            "PID 8524 não encontrado."
        )
        return

    handle = open_process(pid)

    try:
        print(
            "Localizando candidatos..."
        )

        ranges = build_candidates(
            handle
        )

        print(
            f"{len(ranges)} candidatos encontrados."
        )
        print()

        snapshots = {}

        for index, (
            start,
            size,
        ) in enumerate(ranges):
            result = scan_region(
                handle,
                start,
                size,
            )

            if result:
                digest, data, messages = result

                snapshots[index] = (
                    digest,
                    data,
                    messages,
                )

        print(
            "MONITORAMENTO ATIVO"
        )
        print()

        while True:
            for index, (
                start,
                size,
            ) in enumerate(ranges):
                result = scan_region(
                    handle,
                    start,
                    size,
                )

                if not result:
                    continue

                digest, data, messages = result

                previous = snapshots.get(
                    index
                )

                if (
                    previous is None
                    or digest
                    != previous[0]
                ):
                    timestamp = (
                        datetime.now().strftime(
                            "%H:%M:%S.%f"
                        )[:-3]
                    )

                    print()
                    print(
                        f"[{timestamp}] "
                        f"CHANGE #{index} "
                        f"0x{start:X} "
                        f"({size} bytes)"
                    )

                    print(
                        f"  ANTES: "
                        f"{format_messages(previous[2])}"
                        if previous
                        else "  ANTES: (nenhum)"
                    )

                    print(
                        f"  DEPOIS: "
                        f"{format_messages(messages)}"
                    )

                    snapshots[index] = (
                        digest,
                        data,
                        messages,
                    )

            time.sleep(
                SCAN_INTERVAL
            )

    except KeyboardInterrupt:
        print()
        print("Probe encerrado.")

    finally:
        kernel32.CloseHandle(
            handle
        )


if __name__ == "__main__":
    main()
