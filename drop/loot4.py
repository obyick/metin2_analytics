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

LOOT_PREFIX = b"Recebeste "
MESSAGE_MAX_LENGTH = 100

CLUSTER_DISTANCE = 8192
MIN_MESSAGES = 3

RANGE_PADDING = 256

SCAN_INTERVAL = 0.05
DISCOVERY_INTERVAL = 5.0

# Só o cliente que o utilizador está usando para farm.
TARGET_PID = 8524

# Para considerar uma alteração uma inserção real no histórico,
# uma grande parte da sequência anterior precisa continuar presente.
MIN_OVERLAP_RATIO = 0.60

# Evita considerar sequências muito curtas como histórico confiável.
MIN_SEQUENCE_LENGTH_FOR_EVENT = 5


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


def find_target_process():
    try:
        process = psutil.Process(
            TARGET_PID
        )

        if (
            process.name().lower()
            == "metin2client.exe"
        ):
            return process

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


def is_readable(protect):
    base_protect = protect & 0xFF

    return (
        base_protect in READABLE_PROTECTIONS
        and not (protect & PAGE_GUARD)
        and base_protect != PAGE_NOACCESS
    )


def get_regions(handle):
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

        base = int(
            mbi.BaseAddress or 0
        )

        size = int(
            mbi.RegionSize
        )

        if (
            size > 0
            and int(mbi.State)
            == MEM_COMMIT
            and is_readable(
                int(mbi.Protect)
            )
        ):
            regions.append(
                (base, size)
            )

        next_address = (
            base + size
        )

        if next_address <= address:
            break

        address = next_address

        if address >= 0x7FFFFFFFFFFF:
            break

    return regions


def read_memory(
    handle,
    address,
    size,
):
    buffer = ctypes.create_string_buffer(
        size
    )

    bytes_read = ctypes.c_size_t()

    ok = kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )

    if (
        not ok
        or bytes_read.value == 0
    ):
        return b""

    return buffer.raw[
        :bytes_read.value
    ]


def decode_message(raw):
    try:
        text = raw.decode(
            "cp1252",
            errors="strict",
        ).strip()
    except UnicodeDecodeError:
        return None

    if not text.startswith(
        "Recebeste "
    ):
        return None

    if "\ufffd" in text:
        return None

    if len(text) > MESSAGE_MAX_LENGTH:
        return None

    value = text[
        len("Recebeste "):
    ].strip()

    if not value:
        return None

    return text


def extract_messages(
    data,
    base_address,
):
    messages = []

    position = 0

    while True:
        position = data.find(
            LOOT_PREFIX,
            position,
        )

        if position == -1:
            break

        end = data.find(
            b"\x00",
            position,
        )

        if end == -1:
            break

        text = decode_message(
            data[position:end]
        )

        if text is not None:
            messages.append(
                (
                    base_address
                    + position,
                    text,
                )
            )

        position += len(
            LOOT_PREFIX
        )

    return messages


def normalize(text):
    return re.sub(
        r"\s+",
        " ",
        text,
    ).strip()


def is_loot_message(text):
    value = text[
        len("Recebeste "):
    ].strip()

    if not value:
        return False

    # Templates.
    if any(
        marker in value
        for marker in (
            "%s",
            "%d",
            "%u",
            "%x",
            "%dx",
        )
    ):
        return False

    # EXP e mensagens de sistemas.
    if (
        "Pontos de Experiência"
        in value
    ):
        return False

    ignored = (
        "bónus de armazém",
        "recompensa de Guild",
        "pontos adicionais",
        "Golpes Críticos",
        "Golpes Perfuradores",
        "Vontade de Sung Ma",
        "missão",
        "Dobrões",
        "Bênção",
        "Bênçãos",
        "Licença",
        "licença",
        "Cavalo de",
        "Saco de Moedas",
        "Livro do Cavalo",
        "fragmento",
        "Fragmentos",
        "Escamas",
        "Pêlo",
        "Pelo coberto",
        "pelo grosso",
        "pedaço",
        "Pedaço",
    )

    if value.startswith(
        ignored
    ):
        return False

    return True


def extract_loot_sequence(
    data,
    base_address,
):
    sequence = []

    for address, text in extract_messages(
        data,
        base_address,
    ):
        if is_loot_message(text):
            sequence.append(
                (
                    address,
                    normalize(text),
                )
            )

    return sequence


def cluster_messages(messages):
    messages = sorted(
        messages,
        key=lambda item: item[0],
    )

    clusters = []

    for address, text in messages:
        if not clusters:
            clusters.append(
                [(address, text)]
            )
            continue

        previous = clusters[-1][-1][0]

        if (
            address - previous
            <= CLUSTER_DISTANCE
        ):
            clusters[-1].append(
                (address, text)
            )
        else:
            clusters.append(
                [(address, text)]
            )

    return clusters


def discover_candidates(handle):
    regions = get_regions(
        handle
    )

    all_messages = []

    for base, size in regions:
        offset = 0

        while offset < size:
            amount = min(
                CHUNK_SIZE,
                size - offset,
            )

            address = (
                base + offset
            )

            data = read_memory(
                handle,
                address,
                amount,
            )

            if data:
                for (
                    message_address,
                    text,
                ) in extract_messages(
                    data,
                    address,
                ):
                    all_messages.append(
                        (
                            message_address,
                            text,
                        )
                    )

            offset += len(data)

            if not data or len(data) < amount:
                break

    candidates = []

    for cluster in cluster_messages(
        all_messages
    ):
        loot = [
            item
            for item in cluster
            if is_loot_message(
                item[1]
            )
        ]

        if len(loot) < MIN_MESSAGES:
            continue

        start = max(
            0,
            loot[0][0]
            - RANGE_PADDING,
        )

        end = (
            loot[-1][0]
            + RANGE_PADDING
        )

        sequence = [
            (
                address,
                normalize(text),
            )
            for address, text in loot
        ]

        distinct = len(
            set(
                text
                for _, text
                in sequence
            )
        )

        candidates.append(
            {
                "start": start,
                "size": end - start,
                "sequence": sequence,
                "distinct": distinct,
            }
        )

    return candidates


def candidate_key(candidate):
    return (
        candidate["size"],
        len(candidate["sequence"]),
        candidate["distinct"],
    )


def deduplicate_candidates(
    handle,
    candidates,
):
    selected = []
    signatures = set()

    candidates.sort(
        key=candidate_key,
        reverse=True,
    )

    for candidate in candidates:
        data = read_memory(
            handle,
            candidate["start"],
            candidate["size"],
        )

        if not data:
            continue

        sequence = extract_loot_sequence(
            data,
            candidate["start"],
        )

        signature = tuple(
            text
            for _, text
            in sequence
        )

        if not signature:
            continue

        # Cópias idênticas do mesmo histórico
        # não precisam ser monitoradas várias vezes.
        if signature in signatures:
            continue

        signatures.add(
            signature
        )

        candidate[
            "sequence"
        ] = sequence

        selected.append(
            candidate
        )

    return selected


def signatures(sequence):
    return tuple(
        text
        for _, text
        in sequence
    )


def find_new_items(
    previous,
    current,
):
    old = signatures(
        previous
    )

    new = signatures(
        current
    )

    if old == new:
        return []

    if (
        len(old)
        < MIN_SEQUENCE_LENGTH_FOR_EVENT
    ):
        return []

    if (
        len(new)
        < MIN_SEQUENCE_LENGTH_FOR_EVENT
    ):
        return []

    # Inserção no final.
    if (
        len(new) > len(old)
        and new[:len(old)] == old
    ):
        return list(
            current[len(old):]
        )

    # Buffer circular / histórico deslocado:
    # procura a maior sobreposição entre o final
    # do estado antigo e o início do estado novo.
    max_overlap = min(
        len(old),
        len(new),
    )

    best_overlap = 0

    for overlap in range(
        max_overlap,
        0,
        -1,
    ):
        if (
            old[-overlap:]
            == new[:overlap]
        ):
            best_overlap = (
                overlap
            )
            break

    if best_overlap == 0:
        return []

    shorter = min(
        len(old),
        len(new),
    )

    ratio = (
        best_overlap
        / shorter
    )

    if ratio < MIN_OVERLAP_RATIO:
        return []

    additions = list(
        current[best_overlap:]
    )

    if not additions:
        return []

    return additions


def format_loot(text):
    value = text[
        len("Recebeste "):
    ].rstrip(".")

    yang = re.fullmatch(
        r"(\d[\d.]*)\s+Yang",
        value,
        re.IGNORECASE,
    )

    if yang:
        return (
            "Yang x"
            + str(
                int(
                    yang.group(1)
                    .replace(
                        ".",
                        "",
                    )
                )
            )
        )

    return (
        value
        + " x1"
    )


def print_event(
    text
):
    timestamp = (
        datetime.now().strftime(
            "%H:%M:%S.%f"
        )[:-3]
    )

    print(
        f"[{timestamp}] "
        f"PID {TARGET_PID} | "
        f"{format_loot(text)}"
    )


class LootBufferMonitor:
    def __init__(
        self,
        handle,
    ):
        self.handle = handle

        self.candidates = []

        self.last_discovery = (
            0.0
        )

        self.locked_candidate = (
            None
        )

    def discover(
        self,
        initial=False,
    ):
        raw_candidates = (
            discover_candidates(
                self.handle
            )
        )

        candidates = (
            deduplicate_candidates(
                self.handle,
                raw_candidates,
            )
        )

        if initial:
            self.candidates = []

            for candidate in candidates:
                self.candidates.append(
                    {
                        **candidate,
                        "previous": list(
                            candidate[
                                "sequence"
                            ]
                        ),
                    }
                )

        else:
            existing = {
                (
                    candidate["start"],
                    candidate["size"],
                ): candidate
                for candidate
                in self.candidates
            }

            for candidate in candidates:
                key = (
                    candidate["start"],
                    candidate["size"],
                )

                if key in existing:
                    continue

                self.candidates.append(
                    {
                        **candidate,
                        "previous": list(
                            candidate[
                                "sequence"
                            ]
                        ),
                    }
                )

        self.last_discovery = (
            time.monotonic()
        )

        return len(
            candidates
        )

    def scan_candidate(
        self,
        candidate,
    ):
        data = read_memory(
            self.handle,
            candidate["start"],
            candidate["size"],
        )

        if not data:
            return []

        current = extract_loot_sequence(
            data,
            candidate["start"],
        )

        previous = candidate[
            "previous"
        ]

        events = find_new_items(
            previous,
            current,
        )

        candidate[
            "previous"
        ] = current

        return events

    def scan(self):
        # Uma vez encontrado um buffer que realmente
        # produziu um evento válido, ficamos somente nele.
        if self.locked_candidate is not None:
            candidate = self.locked_candidate

            return self.scan_candidate(
                candidate
            )

        for candidate in self.candidates:
            events = self.scan_candidate(
                candidate
            )

            if not events:
                continue

            self.locked_candidate = (
                candidate
            )

            return events

        return []


def main():
    print("=" * 80)
    print("       METIN2 - LOOT MONITOR")
    print("=" * 80)
    print()
    print(
        f"Cliente monitorado: PID {TARGET_PID}"
    )
    print(
        "O outro cliente será ignorado."
    )
    print()
    print(
        "Localizando históricos de loot..."
    )

    process = find_target_process()

    if process is None:
        print()
        print(
            f"PID {TARGET_PID} não encontrado "
            "ou não é metin2client.exe."
        )
        return

    handle = open_process(
        TARGET_PID
    )

    try:
        monitor = LootBufferMonitor(
            handle
        )

        started = time.monotonic()

        candidates = monitor.discover(
            initial=True
        )

        elapsed = (
            time.monotonic()
            - started
        )

        total_sequences = sum(
            len(
                candidate[
                    "previous"
                ]
            )
            for candidate
            in monitor.candidates
        )

        print(
            f"PID {TARGET_PID}: "
            f"{len(monitor.candidates)} "
            f"buffers candidatos | "
            f"{total_sequences} mensagens "
            f"nas sequências | "
            f"{elapsed:.2f}s"
        )

        print()
        print("=" * 80)
        print("MONITORAMENTO ATIVO")
        print("=" * 80)
        print()
        print(
            "Faça drops no personagem."
        )
        print(
            "O programa só considera uma mensagem "
            "quando detecta uma alteração coerente "
            "no histórico."
        )
        print(
            "Quando encontrar o buffer real, "
            "ele ficará travado nele."
        )
        print()
        print(
            "Ctrl+C para encerrar."
        )
        print()

        while True:
            loop_start = time.monotonic()

            events = monitor.scan()

            for _, text in events:
                print_event(
                    text
                )

            now = time.monotonic()

            if (
                now
                - monitor.last_discovery
                >= DISCOVERY_INTERVAL
            ):
                new_candidates = (
                    monitor.discover(
                        initial=False
                    )
                )

                if (
                    monitor.locked_candidate
                    is not None
                ):
                    locked = (
                        monitor.locked_candidate
                    )

                    print(
                        f"[{datetime.now().strftime('%H:%M:%S')}] "
                        f"buffer confirmado: "
                        f"0x{locked['start']:X} "
                        f"({locked['size']} bytes)"
                    )
                elif new_candidates:
                    print(
                        f"[{datetime.now().strftime('%H:%M:%S')}] "
                        f"candidatos atualizados: "
                        f"{new_candidates}"
                    )

            elapsed = (
                time.monotonic()
                - loop_start
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
        kernel32.CloseHandle(
            handle
        )


if __name__ == "__main__":
    main()
