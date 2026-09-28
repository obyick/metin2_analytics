import ctypes
import ctypes.wintypes as wintypes
import re
import time
from collections import Counter
from datetime import datetime


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

TARGET_PID = 8524

# Buffer encontrado durante a investigação.
LOOT_BUFFER_ADDRESS = 0x64EA0800
LOOT_BUFFER_SIZE = 59792

LOOT_PREFIX = b"Recebeste "
MESSAGE_MAX_LENGTH = 200

SCAN_INTERVAL = 0.03
DISCOVERY_INTERVAL = 5.0


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


def verify_buffer(handle):
    mbi = MEMORY_BASIC_INFORMATION()

    result = kernel32.VirtualQueryEx(
        handle,
        ctypes.c_void_p(
            LOOT_BUFFER_ADDRESS
        ),
        ctypes.byref(mbi),
        ctypes.sizeof(mbi),
    )

    if result == 0:
        return False

    base = int(
        mbi.BaseAddress or 0
    )

    size = int(
        mbi.RegionSize
    )

    end = (
        LOOT_BUFFER_ADDRESS
        + LOOT_BUFFER_SIZE
    )

    region_end = (
        base + size
    )

    return (
        base
        <= LOOT_BUFFER_ADDRESS
        and region_end >= end
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
            ctypes.get_last_error()
        )

    return handle


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


def normalize(text):
    return re.sub(
        r"\s+",
        " ",
        text,
    ).strip()


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

    if len(text) > MESSAGE_MAX_LENGTH:
        return None

    value = text[
        len("Recebeste "):
    ].strip()

    if not value:
        return None

    return normalize(text)


def extract_messages(data):
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
                    position,
                    text,
                )
            )

        position += len(
            LOOT_PREFIX
        )

    return messages


def parse_loot(text):
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

    # Algumas mensagens do cliente já trazem quantidade.
    quantity_match = re.fullmatch(
        r"(.+?)\s+x(\d+)",
        value,
        re.IGNORECASE,
    )

    if quantity_match:
        return (
            quantity_match.group(1)
            + " x"
            + quantity_match.group(2)
        )

    return value + " x1"


def print_event(
    text,
    reason,
):
    timestamp = (
        datetime.now().strftime(
            "%H:%M:%S.%f"
        )[:-3]
    )

    print(
        f"[{timestamp}] "
        f"PID {TARGET_PID} | "
        f"{parse_loot(text)}"
    )

    print(
        f"           {text}"
    )

    if reason:
        print(
            f"           {reason}"
        )


def counter_delta(
    previous,
    current,
):
    old_counter = Counter(
        previous
    )

    new_counter = Counter(
        current
    )

    additions = []

    for text, count in (
        new_counter - old_counter
    ).items():
        additions.extend(
            [text] * count
        )

    removals = []

    for text, count in (
        old_counter - new_counter
    ).items():
        removals.extend(
            [text] * count
        )

    return additions, removals


def sequence_changed(
    previous,
    current,
):
    return previous != current


def detect_new_loot(
    previous,
    current,
):
    if not sequence_changed(
        previous,
        current,
    ):
        return []

    additions, removals = (
        counter_delta(
            previous,
            current,
        )
    )

    # Caso normal: um item saiu do histórico
    # e um item novo entrou.
    if (
        len(additions) == 1
        and len(removals) == 1
    ):
        return [
            (
                additions[0],
                "1 entrada nova "
                "detectada no histórico."
            )
        ]

    # Se houve mais de uma atualização entre
    # duas leituras, preserva todos os itens
    # que apareceram.
    if additions:
        return [
            (
                text,
                "Entrada nova detectada "
                "no histórico."
            )
            for text in additions
        ]

    return []


def same_multiset(
    first,
    second,
):
    return (
        Counter(first)
        == Counter(second)
    )


def main():
    print("=" * 80)
    print("       METIN2 - LOOT MONITOR")
    print("=" * 80)
    print()
    print(
        f"Cliente: PID {TARGET_PID}"
    )
    print(
        f"Buffer: 0x{LOOT_BUFFER_ADDRESS:X}"
    )
    print(
        f"Tamanho: {LOOT_BUFFER_SIZE} bytes"
    )
    print()
    print(
        "Este monitor usa diretamente o "
        "buffer de histórico identificado."
    )
    print()

    try:
        handle = open_process(
            TARGET_PID
        )
    except OSError as error:
        print(
            f"Não foi possível abrir o PID "
            f"{TARGET_PID}: {error}"
        )
        return

    try:
        if not verify_buffer(
            handle
        ):
            print(
                "O buffer 0x64EA0800 não está "
                "válido neste cliente."
            )
            print(
                "A região pode ter mudado "
                "após reiniciar o Metin2."
            )
            return

        data = read_memory(
            handle,
            LOOT_BUFFER_ADDRESS,
            LOOT_BUFFER_SIZE,
        )

        previous_messages = [
            text
            for _, text
            in extract_messages(data)
        ]

        print(
            f"Snapshot inicial: "
            f"{len(previous_messages)} "
            "mensagens."
        )

        print()
        print("=" * 80)
        print("MONITORAMENTO ATIVO")
        print("=" * 80)
        print()
        print(
            "Faça um drop e aguarde a mensagem."
        )
        print(
            "Ctrl+C para encerrar."
        )
        print()

        last_verify = (
            time.monotonic()
        )

        while True:
            loop_start = time.monotonic()

            data = read_memory(
                handle,
                LOOT_BUFFER_ADDRESS,
                LOOT_BUFFER_SIZE,
            )

            if not data:
                print(
                    "Falha na leitura do buffer."
                )
                break

            current_messages = [
                text
                for _, text
                in extract_messages(data)
            ]

            events = detect_new_loot(
                previous_messages,
                current_messages,
            )

            for text, reason in events:
                print_event(
                    text,
                    reason,
                )

            previous_messages = (
                current_messages
            )

            now = time.monotonic()

            if (
                now - last_verify
                >= DISCOVERY_INTERVAL
            ):
                if not verify_buffer(
                    handle
                ):
                    print(
                        "O buffer deixou de ser "
                        "válido."
                    )
                    break

                last_verify = now

            elapsed = (
                time.monotonic()
                - loop_start
            )

            time.sleep(
                max(
                    0.001,
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
