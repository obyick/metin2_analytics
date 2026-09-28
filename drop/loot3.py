import ctypes
import ctypes.wintypes as wintypes
import re
import time
from datetime import datetime

import psutil


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000

PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

PAGE_GUARD = 0x100

DISCOVERY_INTERVAL = 3.0
SCAN_INTERVAL = 0.03

PAGE_SIZE = 0x1000
WATCH_PADDING = 512
CHUNK_SIZE = 1024 * 1024

LOOT_PREFIX = b"Recebeste "
MESSAGE_MAX_LENGTH = 100

WRITABLE_PROTECTIONS = {
    PAGE_READWRITE,
    PAGE_WRITECOPY,
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


def is_writable(protect):
    base_protect = protect & 0xFF

    return (
        base_protect in WRITABLE_PROTECTIONS
        and not (protect & PAGE_GUARD)
    )


def get_writable_regions(handle):
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
            and is_writable(protect)
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
            search_from = (
                position
                + len(LOOT_PREFIX)
            )
            continue

        raw = data[position:end]

        if (
            len(raw) > len(LOOT_PREFIX)
            and len(raw)
            <= MESSAGE_MAX_LENGTH
        ):
            text = raw.decode(
                "cp1252",
                errors="replace",
            ).strip()

            if (
                text.startswith("Recebeste ")
                and "\ufffd" not in text
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


def scan_ranges(handle, ranges):
    found = {}

    for base, size in ranges:
        offset = 0

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
                continue

            for (
                message_address,
                text,
            ) in extract_messages(
                data,
                address,
            ):
                found[message_address] = text

            offset += len(data)

            if len(data) < amount:
                break

    return found


def scan_all_writable(handle):
    regions = get_writable_regions(
        handle
    )

    messages = scan_ranges(
        handle,
        regions,
    )

    return regions, messages


def build_watch_ranges(addresses):
    pages = set()

    for address in addresses:
        page = (
            address
            // PAGE_SIZE
        ) * PAGE_SIZE

        start = max(
            0,
            page - WATCH_PADDING,
        )

        end = (
            page
            + PAGE_SIZE
            + WATCH_PADDING
        )

        start = (
            start
            // PAGE_SIZE
        ) * PAGE_SIZE

        end = (
            (
                end
                + PAGE_SIZE
                - 1
            )
            // PAGE_SIZE
        ) * PAGE_SIZE

        current = start

        while current < end:
            pages.add(current)
            current += PAGE_SIZE

    sorted_pages = sorted(pages)

    if not sorted_pages:
        return []

    ranges = []

    start = sorted_pages[0]
    previous = sorted_pages[0]

    for page in sorted_pages[1:]:
        if page == previous + PAGE_SIZE:
            previous = page
            continue

        ranges.append(
            (
                start,
                previous
                + PAGE_SIZE
                - start,
            )
        )

        start = page
        previous = page

    ranges.append(
        (
            start,
            previous
            + PAGE_SIZE
            - start,
        )
    )

    return ranges


def normalize_message(text):
    return re.sub(
        r"\s+",
        " ",
        text,
    ).strip()


def parse_loot(text):
    value = text[
        len("Recebeste "):
    ].strip()

    yang_match = re.fullmatch(
        r"(\d[\d.]*)\s+Yang\.?",
        value,
        re.IGNORECASE,
    )

    if yang_match:
        return {
            "item": "Yang",
            "quantity": int(
                yang_match.group(1).replace(
                    ".",
                    "",
                )
            ),
        }

    return {
        "item": value.rstrip("."),
        "quantity": 1,
    }


def print_loot(pid, text):
    loot = parse_loot(text)

    timestamp = datetime.now().strftime(
        "%H:%M:%S.%f"
    )[:-3]

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

        self.messages = {}
        self.watch_ranges = []

        self.last_discovery = 0.0

    def close(self):
        if self.handle:
            kernel32.CloseHandle(
                self.handle
            )
            self.handle = None

    def initial_scan(self):
        _, messages = scan_all_writable(
            self.handle
        )

        self.messages = messages

        self.watch_ranges = (
            build_watch_ranges(
                messages.keys()
            )
        )

        self.last_discovery = (
            time.monotonic()
        )

    def fast_scan(self):
        if not self.watch_ranges:
            return {}

        return scan_ranges(
            self.handle,
            self.watch_ranges,
        )

    def rediscover(self):
        _, discovered = scan_all_writable(
            self.handle
        )

        new_ranges = build_watch_ranges(
            discovered.keys()
        )

        self.watch_ranges = new_ranges

        return discovered

    def monitor(self):
        current = self.fast_scan()

        events = {}

        for address, text in current.items():
            previous = self.messages.get(
                address
            )

            if previous != text:
                normalized = normalize_message(
                    text
                )

                events[normalized] = text

        self.messages.update(current)

        for text in events.values():
            print_loot(
                self.pid,
                text,
            )

        now = time.monotonic()

        if (
            now - self.last_discovery
            >= DISCOVERY_INTERVAL
        ):
            discovered = self.rediscover()

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

                start = time.monotonic()

                monitor.initial_scan()

                elapsed = (
                    time.monotonic()
                    - start
                )

                print(
                    f"PID {process.pid}: "
                    f"{len(monitor.messages)} "
                    "mensagens existentes | "
                    f"{len(monitor.watch_ranges)} "
                    "faixas monitoradas | "
                    f"{elapsed:.2f}s"
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

            elapsed = (
                time.monotonic()
                - start
            )

            time.sleep(
                max(
                    0.005,
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
