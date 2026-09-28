import ctypes
import ctypes.wintypes as wintypes
import re
import time
from datetime import datetime

import psutil


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

READABLE_PROTECTIONS = {
    0x02,
    0x04,
    0x08,
    0x20,
    0x40,
    0x80,
}

CHUNK_SIZE = 1024 * 1024
SCAN_INTERVAL = 0.20
DISCOVERY_INTERVAL = 5.0

LOOT_PREFIX = b"Recebeste "

MESSAGE_MAX_LENGTH = 200

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


def find_processes():
    processes = []

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
                processes.append(process)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):
            continue

    return sorted(
        processes,
        key=lambda process: process.pid,
    )


def open_process(pid):
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION
        | PROCESS_VM_READ,
        False,
        pid,
    )

    if not handle:
        raise OSError(
            ctypes.get_last_error(),
        )

    return handle


def is_readable(protect):
    base_protect = protect & 0xFF

    return (
        base_protect in READABLE_PROTECTIONS
        and not (protect & PAGE_GUARD)
        and base_protect != PAGE_NOACCESS
    )


def get_readable_regions(handle):
    regions = []

    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)

    while True:
        result = kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            mbi_size,
        )

        if result == 0:
            break

        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize)
        state = int(mbi.State)
        protect = int(mbi.Protect)

        if (
            size > 0
            and state == MEM_COMMIT
            and is_readable(protect)
        ):
            regions.append(
                (base, size)
            )

        next_address = base + size

        if next_address <= address:
            break

        address = next_address

        if address >= 0x7FFFFFFFFFFF:
            break

    return regions


def read_memory(handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()

    ok = kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )

    if not ok or bytes_read.value == 0:
        return b""

    return buffer.raw[:bytes_read.value]


def extract_messages(data, base_address):
    messages = []

    search_from = 0

    while True:
        position = data.find(
            LOOT_PREFIX,
            search_from,
        )

        if position == -1:
            break

        end = data.find(
            b"\x00",
            position,
        )

        if end == -1:
            end = min(
                len(data),
                position + MESSAGE_MAX_LENGTH,
            )

        raw = data[position:end]

        if len(raw) > len(LOOT_PREFIX):
            try:
                text = raw.decode(
                    "cp1252",
                    errors="replace",
                ).strip()
            except Exception:
                text = ""

            if text.startswith(
                "Recebeste "
            ):
                messages.append(
                    (
                        base_address + position,
                        text,
                    )
                )

        search_from = (
            position
            + len(LOOT_PREFIX)
        )

    return messages


def scan_messages(handle, regions):
    found = {}

    for base, size in regions:
        offset = 0
        overlap = len(LOOT_PREFIX) + MESSAGE_MAX_LENGTH

        previous_tail = b""

        while offset < size:
            amount = min(
                CHUNK_SIZE,
                size - offset,
            )

            address = base + offset

            data = read_memory(
                handle,
                address,
                amount,
            )

            if not data:
                offset += amount
                previous_tail = b""
                continue

            searchable = (
                previous_tail + data
            )

            searchable_base = (
                address
                - len(previous_tail)
            )

            for (
                message_address,
                text,
            ) in extract_messages(
                searchable,
                searchable_base,
            ):
                found[message_address] = text

            previous_tail = data[
                -overlap:
            ]

            offset += len(data)

            if len(data) < amount:
                break

    return found


def parse_loot(text):
    value = text[
        len("Recebeste "):
    ].strip()

    match = re.fullmatch(
        r"(.+?)\s+(\d[\d.]*)\s+Yang\.",
        value,
        re.IGNORECASE,
    )

    if match:
        return {
            "item": "Yang",
            "quantity": int(
                match.group(2).replace(
                    ".",
                    "",
                )
            ),
            "raw": text,
        }

    match = re.fullmatch(
        r"(.+?)\s+x?(\d+)\s*$",
        value,
    )

    if match:
        return {
            "item": match.group(1).strip(),
            "quantity": int(
                match.group(2)
            ),
            "raw": text,
        }

    return {
        "item": value.rstrip("."),
        "quantity": 1,
        "raw": text,
    }


def print_loot(pid, address, text):
    loot = parse_loot(text)

    timestamp = datetime.now().strftime(
        "%H:%M:%S"
    )

    print(
        f"[{timestamp}] "
        f"PID {pid} | "
        f"{loot['item']} "
        f"x{loot['quantity']}"
    )

    print(
        f"           {text}"
    )


class ClientMonitor:
    def __init__(self, pid):
        self.pid = pid
        self.handle = open_process(pid)
        self.regions = []
        self.messages = {}
        self.last_discovery = 0.0

    def close(self):
        if self.handle:
            kernel32.CloseHandle(
                self.handle
            )
            self.handle = None

    def refresh_regions(self):
        self.regions = get_readable_regions(
            self.handle
        )

    def initial_scan(self):
        self.refresh_regions()

        self.messages = scan_messages(
            self.handle,
            self.regions,
        )

        self.last_discovery = time.monotonic()

    def monitor(self):
        current = scan_messages(
            self.handle,
            self.regions,
        )

        for address, text in current.items():
            previous = self.messages.get(
                address
            )

            if previous == text:
                continue

            if previous is None:
                # A mensagem nova pode ter surgido
                # em um endereço que já estava
                # registrado no snapshot inicial.
                print_loot(
                    self.pid,
                    address,
                    text,
                )
            else:
                print_loot(
                    self.pid,
                    address,
                    text,
                )

        self.messages = current

        now = time.monotonic()

        if (
            now - self.last_discovery
            >= DISCOVERY_INTERVAL
        ):
            self.refresh_regions()

            discovered = scan_messages(
                self.handle,
                self.regions,
            )

            for address, text in discovered.items():
                if address not in self.messages:
                    self.messages[address] = text

            self.last_discovery = now


def main():
    print(
        "========================================"
    )
    print(
        "       METIN2 - LOOT MONITOR"
    )
    print(
        "========================================"
    )
    print()
    print(
        "Monitorando mensagens 'Recebeste ...'"
    )
    print(
        "Ctrl+C para encerrar."
    )
    print()

    monitors = {}

    try:
        processes = find_processes()

        if not processes:
            raise RuntimeError(
                "metin2client.exe não encontrado."
            )

        print(
            f"Clientes encontrados: "
            f"{len(processes)}"
        )

        for process in processes:
            try:
                monitor = ClientMonitor(
                    process.pid
                )

                print(
                    f"PID {process.pid}: "
                    "fazendo snapshot inicial..."
                )

                monitor.initial_scan()

                print(
                    f"PID {process.pid}: "
                    f"{len(monitor.messages)} "
                    "mensagens existentes."
                )

                monitors[process.pid] = (
                    monitor
                )

            except OSError as error:
                print(
                    f"PID {process.pid}: "
                    f"falha ao abrir: {error}"
                )

        if not monitors:
            raise RuntimeError(
                "Nenhum cliente pôde ser aberto."
            )

        print()
        print(
            "========================================"
        )
        print(
            "MONITORAMENTO ATIVO"
        )
        print(
            "========================================"
        )
        print(
            "Colete um item no jogo."
        )
        print()

        while True:
            start = time.monotonic()

            for pid in list(
                monitors.keys()
            ):
                monitor = monitors[pid]

                try:
                    monitor.monitor()

                except OSError:
                    print(
                        f"[{datetime.now().strftime('%H:%M:%S')}] "
                        f"PID {pid}: cliente encerrado."
                    )

                    monitor.close()
                    del monitors[pid]

            current_processes = {
                process.pid
                for process in find_processes()
            }

            for pid in (
                current_processes
                - set(monitors)
            ):
                try:
                    monitor = ClientMonitor(
                        pid
                    )

                    monitor.initial_scan()

                    monitors[pid] = monitor

                    print(
                        f"PID {pid}: "
                        "novo cliente detectado."
                    )

                except OSError:
                    pass

            if not monitors:
                print(
                    "Nenhum cliente ativo. "
                    "Aguardando..."
                )

            elapsed = (
                time.monotonic()
                - start
            )

            time.sleep(
                max(
                    0.01,
                    SCAN_INTERVAL
                    - elapsed,
                )
            )

    except KeyboardInterrupt:
        print()
        print("Monitor encerrado.")

    finally:
        for monitor in monitors.values():
            monitor.close()


if __name__ == "__main__":
    main()
