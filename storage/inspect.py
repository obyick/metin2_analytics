import ctypes
import ctypes.wintypes as wt

PID = 2768

RANGES = [
    (0x836CC000, 0x836CD200),
    (0x88641000, 0x88642000),
]

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE

kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE,
    wt.LPCVOID,
    wt.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wt.BOOL


def open_process():
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        PID,
    )

    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    return handle


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

    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    return buffer.raw[:read.value]


def snapshot(handle):
    result = {}

    for start, end in RANGES:
        data = read_memory(handle, start, end - start)

        for offset in range(0, len(data) - 3, 4):
            address = start + offset
            value = int.from_bytes(
                data[offset:offset + 4],
                "little",
                signed=False,
            )

            result[address] = value

    return result


def compare(states):
    names = list(states)

    print()
    print("=== ALTERAÇÕES ENTRE ESTADOS ===")
    print()

    addresses = sorted(
        set().union(*(state.keys() for state in states.values()))
    )

    count = 0

    for address in addresses:
        values = [
            states[name].get(address)
            for name in names
        ]

        if len(set(values)) <= 1:
            continue

        print(f"0x{address:08X}")

        for name, value in zip(names, values):
            if value is None:
                print(f"  {name}: <N/A>")
            else:
                print(f"  {name}: {value:10d}  0x{value:08X}")

        print()
        count += 1

    print(f"Total de DWORDs diferentes: {count}")


def main():
    handle = open_process()

    print(f"PID: {PID}")
    print()
    print("Faça exatamente nesta ordem:")
    print()
    print("1. Coloque o Ornamento no SLOT A.")
    input("   ENTER para capturar A... ")
    state_a = snapshot(handle)

    print()
    print("2. Mova o Ornamento para o SLOT B.")
    input("   ENTER para capturar B... ")
    state_b = snapshot(handle)

    print()
    print("3. Mova o Ornamento para o SLOT C.")
    input("   ENTER para capturar C... ")
    state_c = snapshot(handle)

    states = {
        "A": state_a,
        "B": state_b,
        "C": state_c,
    }

    compare(states)


if __name__ == "__main__":
    main()