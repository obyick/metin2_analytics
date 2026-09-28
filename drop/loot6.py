import ctypes
import ctypes.wintypes as wintypes
import re
import time
from datetime import datetime

import psutil


# --- Win32 ---------------------------------------------------------------

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

READABLE_PROTECTIONS = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}

PAGE_SIZE = 0x1000

# --- Tuning ------------------------------------------------------------------
# O scan completo de memória (scan_full_memory) é caro: só roda na
# descoberta inicial e, depois, raramente, para pegar buffers novos.
# O loop "quente" (fast_scan) só lê as janelas já conhecidas.

FAST_SCAN_INTERVAL = 0.05      # loop quente: 20x/s, só lê algumas KB
DISCOVERY_INTERVAL = 10.0      # scan completo: caro, raro
PROCESS_CHECK_INTERVAL = 2.0   # procurar novos clientes metin2client.exe

CLUSTER_GAP = 16 * 1024        # matches a até 16KB um do outro = mesma janela
WATCH_PADDING = 4096           # margem extra na janela vigiada, p/ crescimento

DEDUP_WINDOW = 0.3             # ecos do mesmo texto dentro dessa janela
                                # de tempo são descartados (cópias-espelho
                                # tendem a mudar juntas, no mesmo tick)

CHUNK_SIZE = 1024 * 1024

LOOT_PREFIX = b"Recebeste "
MESSAGE_MAX_LENGTH = 200

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


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


kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
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


# --- Processo / memória crua ------------------------------------------------

def find_processes():
    processes = []

    for process in psutil.process_iter(["pid", "name"]):
        try:
            name = process.info["name"]

            if name and name.lower() == "metin2client.exe":
                processes.append(process)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return sorted(processes, key=lambda process: process.pid)


def open_process(pid):
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid,
    )

    if not handle:
        raise OSError(ctypes.get_last_error())

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
            handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size
        )

        if result == 0:
            break

        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize)

        if size > 0 and int(mbi.State) == MEM_COMMIT and is_readable(int(mbi.Protect)):
            regions.append((base, size))

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
        handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)
    )

    if not ok or bytes_read.value == 0:
        return b""

    return buffer.raw[: bytes_read.value]


# --- Extração de mensagens ---------------------------------------------------

def extract_messages(data, base_address):
    """Retorna [(endereço, texto), ...] em ordem crescente de endereço."""

    messages = []
    search_from = 0

    while True:
        position = data.find(LOOT_PREFIX, search_from)

        if position == -1:
            break

        end = data.find(b"\x00", position)

        if end == -1:
            end = min(len(data), position + MESSAGE_MAX_LENGTH)

        raw = data[position:end]

        if len(raw) > len(LOOT_PREFIX):
            try:
                text = raw.decode("cp1252", errors="replace").strip()
            except Exception:
                text = ""

            if text.startswith("Recebeste "):
                messages.append((base_address + position, text))

        search_from = position + len(LOOT_PREFIX)

    return messages


def scan_region(handle, base, size):
    """Lê uma região em pedaços (com sobreposição na borda) e extrai
    mensagens. Usado só na descoberta completa (cara)."""

    found = {}
    offset = 0
    overlap = len(LOOT_PREFIX) + MESSAGE_MAX_LENGTH
    previous_tail = b""

    while offset < size:
        amount = min(CHUNK_SIZE, size - offset)
        address = base + offset
        data = read_memory(handle, address, amount)

        if not data:
            offset += amount
            previous_tail = b""
            continue

        searchable = previous_tail + data
        searchable_base = address - len(previous_tail)

        for message_address, text in extract_messages(searchable, searchable_base):
            found[message_address] = text

        previous_tail = data[-overlap:]
        offset += len(data)

        if len(data) < amount:
            break

    return found


def scan_full_memory(handle):
    """Scan lento e completo de toda a memória legível. Só roda na
    descoberta inicial e nas revalidações periódicas."""

    found = {}

    for base, size in get_readable_regions(handle):
        found.update(scan_region(handle, base, size))

    return found


# --- Agrupamento (só para montar janelas de leitura eficientes) -------------
#
# NÃO tentamos mais adivinhar qual cópia é "a real": o jogo mantém várias
# cópias do mesmo log espalhadas pela memória e elas não são idênticas
# byte-a-byte entre si (cada uma captura o texto num ponto ligeiramente
# diferente), então comparar conteúdo pra escolher "a canônica" é frágil
# e, na prática, quase nunca agrupa nada. Em vez disso: vigiamos TODAS as
# cópias (isso é barato, são só algumas KB cada) e deduplicamos na hora
# de decidir o que imprimir — ver DEDUP_WINDOW abaixo.

def cluster_matches(matches, gap=CLUSTER_GAP):
    if not matches:
        return []

    items = sorted(matches.items())
    clusters = [[items[0]]]

    for address, text in items[1:]:
        last_address, _ = clusters[-1][-1]

        if address - last_address <= gap:
            clusters[-1].append((address, text))
        else:
            clusters.append([(address, text)])

    return clusters


def build_watch_range(cluster):
    first_address = cluster[0][0]
    last_address, last_text = cluster[-1]

    last_length = len(last_text.encode("cp1252", errors="replace"))

    start = max(0, first_address - WATCH_PADDING)
    end = last_address + last_length + WATCH_PADDING

    start = (start // PAGE_SIZE) * PAGE_SIZE
    end = ((end + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE

    return start, end - start


def normalize_message(text):
    return re.sub(r"\s+", " ", text).strip()


# --- Parsing / print ---------------------------------------------------------

def parse_loot(text):
    value = text[len("Recebeste "):].strip()

    yang_match = re.fullmatch(r"(\d[\d.]*)\s+Yang\.?", value, re.IGNORECASE)

    if yang_match:
        return {
            "item": "Yang",
            "quantity": int(yang_match.group(1).replace(".", "")),
        }

    quantity_match = re.fullmatch(r"(.+?)\s+x?(\d+)\s*\.?", value)

    if quantity_match:
        return {
            "item": quantity_match.group(1).strip(),
            "quantity": int(quantity_match.group(2)),
        }

    return {"item": value.rstrip("."), "quantity": 1}


def print_loot(pid, text):
    loot = parse_loot(text)
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    print(f"[{timestamp}] PID {pid} | {loot['item']} x{loot['quantity']}")
    print(f"           {text}")


# --- Monitor por cliente ------------------------------------------------------

class ClientMonitor:
    def __init__(self, pid):
        self.pid = pid
        self.handle = open_process(pid)
        self.watch_ranges = []
        self.known = {}          # endereço -> texto (estado atual daquele slot)
        self.recent_prints = {}  # texto normalizado -> timestamp da última impressão
        self.last_discovery = 0.0

    def close(self):
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def discover(self):
        matches = scan_full_memory(self.handle)
        clusters = cluster_matches(matches)

        self.watch_ranges = [build_watch_range(cluster) for cluster in clusters]

        # Qualquer endereço que ainda não vigiávamos entra com um estado
        # "linha de base" silencioso, em vez de disparar um evento falso.
        for address, text in matches.items():
            self.known.setdefault(address, text)

        self.last_discovery = time.monotonic()

    def initial_scan(self):
        self.discover()

    def fast_scan(self):
        found = {}

        for base, size in self.watch_ranges:
            data = read_memory(self.handle, base, size)

            if not data:
                continue

            for address, text in extract_messages(data, base):
                found[address] = text

        return found

    def monitor(self):
        current = self.fast_scan()
        now = time.monotonic()

        # Poda leve do cache de dedup: sem isso ele cresce pra sempre
        # numa sessão longa.
        if self.recent_prints:
            self.recent_prints = {
                key: ts
                for key, ts in self.recent_prints.items()
                if now - ts < DEDUP_WINDOW
            }

        for address, text in sorted(current.items()):
            if self.known.get(address) == text:
                continue  # esse slot não mudou

            normalized = normalize_message(text)
            last_printed = self.recent_prints.get(normalized)

            if last_printed is not None and now - last_printed < DEDUP_WINDOW:
                continue  # eco de uma cópia-espelho, já impresso há pouco

            print_loot(self.pid, text)
            self.recent_prints[normalized] = now

        self.known.update(current)

        if now - self.last_discovery >= DISCOVERY_INTERVAL:
            self.discover()


# --- Main ---------------------------------------------------------------------

def main():
    print("=" * 60)
    print("       METIN2 - LOOT MONITOR (ended)")
    print("=" * 60)
    print()
    print("Monitorando mensagens 'Recebeste ...'")
    print("Ctrl+C para encerrar.")
    print()

    monitors = {}
    last_process_check = 0.0

    try:
        processes = find_processes()

        if not processes:
            raise RuntimeError("metin2client.exe não encontrado.")

        print(f"Clientes encontrados: {len(processes)}")

        for process in processes:
            try:
                monitor = ClientMonitor(process.pid)

                print(f"PID {process.pid}: fazendo scan inicial...")
                start = time.monotonic()

                monitor.initial_scan()

                elapsed = time.monotonic() - start

                print(
                    f"PID {process.pid}: "
                    f"{len(monitor.known)} mensagens existentes | "
                    f"{len(monitor.watch_ranges)} janela(s) vigiada(s) | "
                    f"{elapsed:.2f}s"
                )

                monitors[process.pid] = monitor

            except OSError as error:
                print(f"PID {process.pid}: falha ao abrir: {error}")

        if not monitors:
            raise RuntimeError("Nenhum cliente pôde ser aberto.")

        print()
        print("=" * 60)
        print("MONITORAMENTO ATIVO")
        print("=" * 60)
        print("Colete um item no jogo.")
        print()

        while True:
            start = time.monotonic()

            for pid in list(monitors.keys()):
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

            if start - last_process_check >= PROCESS_CHECK_INTERVAL:
                current_pids = {process.pid for process in find_processes()}

                for pid in current_pids - set(monitors):
                    try:
                        monitor = ClientMonitor(pid)
                        monitor.initial_scan()
                        monitors[pid] = monitor

                        print(f"PID {pid}: novo cliente detectado.")

                    except OSError:
                        pass

                last_process_check = start

            if not monitors:
                print("Nenhum cliente ativo. Aguardando...")

            elapsed = time.monotonic() - start

            time.sleep(max(0.005, FAST_SCAN_INTERVAL - elapsed))

    except KeyboardInterrupt:
        print()
        print("Monitor encerrado.")

    finally:
        for monitor in monitors.values():
            monitor.close()


if __name__ == "__main__":
    main()
