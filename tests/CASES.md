# Manual test cases

## CT01 - Explorer settings

1. Open `regedit` at `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`
2. Toggle `ShowSuperHidden` between `0` and `1`
3. Run `unhide.exe --output results`
4. Expected: the `HideProtected` value in the report reflects the registry

## CT02 - Simulated protected file

1. Create `C:\Test\hidden.txt`
2. Run `attrib +S +H C:\Test\hidden.txt`
3. Run `unhide.exe --path C:\Test`
4. Expected: item `os-protected-hidden` listed in the console
5. Clean with `attrib -S -H C:\Test\hidden.txt`

## CT03 - Double extension

1. Create `C:\Test\note.pdf.exe`
2. Run `unhide.exe --path C:\Test --full`
3. Expected: item `double-extension` with `[Detected!]`

## CT04 - Clean Explorer

1. Machine with no known injection
2. Run as administrator
3. Expected: no `Detected hooks` section and verdict `CLEAN` or `INFORMATIVE`

## CT05 - File report

1. Run `unhide.exe --output results`
2. Expected: `report_<date>.txt` and `.json` in `results`
3. Without `--output`, nothing is written to disk
