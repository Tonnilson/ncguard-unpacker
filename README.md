# ncguard-unpacker

Static unpacker for ncguard-packed AMD64 executables (e.g. Blade & Soul's `BNSR.exe`). It reads the
packed file, decrypts and decompresses the embedded modules, and writes the main module back out as
a loadable PE. Nothing is executed and nothing but the final binary is written to disk.

## Usage

```
ncguard-unpacker <packed.exe> [outdir]
```

- `outdir` defaults to the folder containing `ncguard-unpacker.exe`.
- The output is named after the input and its file version, e.g. `BNSR_0.5.10646.4.exe`
  (`BNSR_unpacked.exe` if the image has no version resource).
- Progress and a sanity check of the rebuilt headers are printed to the console.

## Keys

The payloads are XORed with two 48-byte keys (`KEY0` for the first record, `KEYN` for the rest).
The unpacker recovers them from the packer stub in the input itself. If that fails, for example
after a packer update, it falls back to `keys.txt` next to the executable:

```
KEY0 = 1fa94f38...
KEYN = 22caa631...
```

`keys.txt` is copied to the output folder on build.

## How it works

1. Locate the obfuscated records table that describes each packed payload.
2. Extract `KEY0`/`KEYN` from the stub's stack-built key bytes, validated against the records.
3. Strip each payload's XOR layers and decompress its regions (ncguard's LZSS variant).
4. Reassemble module images from their sections; the largest module is the game itself.
5. Classify the module's directory stream back into PE data directories and recover the entry
   point from the CRT's security-cookie initializer.
6. Write a flat PE (RVA == file offset) with a synthesized header and recovered section names.

## Tested against
- BNSR.exe LIVE Client [0.5.10646.4]
- BNSR.exe NEO Client [0.8.10250.31]

Should work for others as well, but I haven't tested it.

## Disclaimer

This project is provided for educational and research purposes only, to study executable packing
and PE file structure. It is not affiliated with or endorsed by NCSOFT or the authors of ncguard.
Use it only on software you are permitted to analyze, and in accordance with the applicable terms
of service and laws. The author accepts no responsibility for misuse; the software is provided
as is, without warranty of any kind.