# Unhide Usermode

C++ forensic tool for Windows that detects user-mode hidden files and programs hooking Explorer to hide content.

No external dependencies. Windows API only. Focused on precision and zero false positives.

## What it detects

- Files hidden by the `Hide protected operating system files` option
- Files with the hidden attribute, double extensions, and Unicode-camouflaged names
- Divergence between the Win32 view and the native view (`FindFirstFile` vs `NtQueryDirectoryFile`)
- Unsigned modules loaded inside `explorer.exe`
- Inline hooks in listing APIs with a destination outside the legitimate module
- Persistences that touch Explorer (`AppInit_DLLs`, shell objects, Explorer tasks)

## Accuracy criteria

| Verdict | Criteria |
|---|---|
| `CONFIRMED` | Hook with an external destination, or Win32 vs Native divergence combined with a risky module |
| `SUSPICIOUS` | Unsigned module, risky persistence, or isolated camouflage |
| `INFORMATIVE` | Only legitimate Microsoft `+S +H` files |
| `CLEAN` | Nothing relevant found |

Signed `+S +H` files in `System32`, `SysWOW64`, and `WinSxS` never raise alerts. Only double evidence produces `CONFIRMED`, shown as `Type: Detected!`.

## Built-in whitelist

- Any DLL with a valid signature inside `explorer.exe` is ignored (Microsoft, OneDrive, 7-Zip, Visual Studio, and other legitimate vendors)
- `kernel32` jumps into `kernelbase` are legitimate forwarding, not hooks
- `desktop.ini`, `container.dat`, `ntuser.ini`, `ActivationStore` logs, registry transactions (`.regtrans-ms`, `.blf`), and caches (`INetCache`, `INetCookies`, `INetHistory`, `Packages`) don't pollute the report
- Windows vaults (`Protect`, `Credentials`), services (`DRM`, `WinMSIPC`, `WwanSvc`), and profile skeleton (`Default`, `Public`) are ignored
- `.vs` folders and junctions (reparse points) are skipped during the scan, no duplicates in the report
- An unsigned module in a Windows or `Program Files` folder becomes low risk and doesn't change the verdict by itself

## Layout

```text
unhide-usermode
├── unhide.sln
├── unhide.vcxproj
├── unhide.vcxproj.filters
├── CMakeLists.txt
├── src
│   ├── main.cpp
│   ├── core
│   ├── utils
│   ├── scan
│   ├── detection
│   └── report
├── include
│   └── unhide
├── results
└── tests
```

## Standard build (Visual Studio)

1. Open `unhide.sln` in Visual Studio 2022
2. Select `Release | x64`
3. Press `Ctrl+Shift+B`
4. The binary lands in `bin\x64\Release\unhide.exe`

Command-line alternative:

```bat
msbuild unhide.sln /p:Configuration=Release /p:Platform=x64
```

## Other build option

Direct CMake:

```bat
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Prerequisite: Visual Studio 2022 with the C++ workload, or MinGW-w64.

## Usage

Run `cmd` as administrator from the binary folder:

```bat
unhide.exe
unhide.exe --full
unhide.exe --path C:\Users --output results
```

Parameters:

| Parameter | Effect |
|---|---|
| `--path <folder>` | Scans only the given folder. Repeatable. |
| `--full` | Scans all fixed drives. Default scans profile, AppData, and Users. |
| `--output <folder>` | Also saves `.txt` + `.json` there. Optional. |
| `--help` | Shows help. |

Old `--caminho`, `--completo`, `--saida`, and `--ajuda` still work as aliases.

Everything is shown in this console: counts, findings with `[Detected!]` tags, and the final verdict. Nothing is written to disk unless you pass `--output`, which saves `.txt` + `.json` reports as `report_<date>.txt`.

Example:

```text
    scanning... C:\Users\Public
--------------------------------------------------
Hidden files (1):
  [1] C:\Users\l\Desktop\Nova pasta\cache\data\teste_oculto.exe
      Hidden+System | os-protected-hidden
--------------------------------------------------
FINAL VERDICT: SUSPICIOUS
Hidden files outside the standard Windows pattern. No active hook, manual review required.
Evidence:
  * Unknown hidden file: C:\Users\l\Desktop\Nova pasta\cache\data\teste_oculto.exe
```

## Methodology in short

- `ShowSuperHidden = 0` explains invisible `+S +H` files with no malware involved
- Compares `FindFirstFile` against `NtQueryDirectoryFile`: a `kernel32` hook usually filters only the high level
- A hook only confirms with a destination outside the module image; internal hotpatch is ignored
- Disabled `AppInit` never raises alerts

## Requirements

- Windows 10 or 11 x64
- Administrator recommended
- No extra installation once built

## License

MIT. See `LICENSE`.
