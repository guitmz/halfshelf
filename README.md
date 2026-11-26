# halfshelf

halfshelf is a small userland loader for SHELF style binaries on Linux x64, written in FASM. A SHELF binary here is a static PIE with a single PT_LOAD segment, plus optional PT_DYNAMIC and PT_TLS. The loader maps it, applies relocations, sets up TLS, builds a fresh stack and jumps to the entry point without calling `execve`.

This is the companion code for the tmp.0ut article at https://tmpout.sh/5/14.html

It is a sibling of [halfexec](https://github.com/guitmz/halfexec), a more general userland ELF loader that also handles dynamic and fixed address binaries.

## Tools

* `halfshelf` runs a normal SHELF ELF file
* `headshelf` runs a headless payload, meaning the ELF and program headers are gone and a small metadata file describes what is needed to load it
* `strip_headers` turns a SHELF ELF into that headless payload and its metadata file, in text or binary form

`headshelf` can also read the payload from stdin and stage it in a memfd, so the payload never needs a path on disk.

## Limits

* Target files must be 1 MB or smaller
* Only one PT_LOAD segment is accepted
* No interpreter, so dynamic binaries are refused
* Only a small set of relocations is handled
* Linux x64 only

## Build

You need `fasm`, and `gcc` for the test programs.

```sh
make
```

This builds `halfshelf` and `headshelf` in the repo root and `strip_headers` in `build/`.

## Usage

Run a SHELF binary.

```sh
./halfshelf /path/to/program [args...]
```

Strip the headers and run the headless payload.

```sh
build/strip_headers program program.payload program.meta
./headshelf program.payload program.meta [args...]
```

Use `--headless-bin` with `strip_headers` for a binary metadata file instead of text. `headshelf` detects the format by itself.

Run the payload straight from stdin.

```sh
cat program.payload | ./headshelf --memfd program.meta [args...]
```

Set `HALFSHELF_DEBUG=1` to print what the loader is doing.

## Building a SHELF binary

The test programs show how. They are linked as static PIE with the linker script in `tests/static-pie.ld`.

```sh
gcc -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -static-pie -Wl,--no-eh-frame-hdr -Wl,-T,tests/static-pie.ld \
    -o program program.c
```

## Tests

```sh
make run
make corrupt-tests
```

`make run` builds the samples into `build/` and runs them through both loaders, in file mode and memfd mode, checking the exit code. One sample, `tests/test_nolibc.c`, has no libc, so nothing in it redoes the loader's relocation, TLS or stack alignment work, and it only passes when the loader got those right. `make corrupt-tests` feeds broken metadata, a bad program header offset and oversized files, and checks that each one is refused with exit status 1 instead of a crash. `make inspect` shows the ELF layout of the samples and `make clean` removes everything.

## Layout

* `halfshelf.asm` is the SHELF loader
* `headshelf.asm` is the headless loader
* `strip_headers/` holds the header stripping tool
* `utils.inc` holds syscall numbers, constants and structures
* `loader/` holds shared code for validation, relocation, stack setup, debug tracing, error exits and data
* `tests/` holds the sample programs and linker script
