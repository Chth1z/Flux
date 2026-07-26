# Android 16 KiB ELF compatibility with NDK r27

- Status: implementation guidance for the B3.1 Android release gate
- NDK version in scope: r27d (`27.3.13750724`) [A2], tag commit
  `13447502af3f446b0010f618b52ea18819b3dfb5`
- External sources accessed: 2026-07-26
- Scope: ELF link and verification policy; APK zip alignment is recorded only to keep the two
  alignment layers distinct

## Decision for Flux

For every `aarch64-linux-android` and `x86_64-linux-android` final link performed with NDK r27,
pass both of the linker options required by the current Android compatibility guide:

```text
-Wl,-z,max-page-size=16384
-Wl,-z,common-page-size=16384
```

NDK r27 does **not** enable 16 KiB-compatible output by default. Do not rely on the CMake setting
`ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES` or the ndk-build setting
`APP_SUPPORT_FLEXIBLE_PAGE_SIZES` for a Cargo build: those settings are interpreted only by the
NDK's CMake/ndk-build files, and the r27d implementations inject only `max-page-size=16384`.
Cargo invokes the configured linker without evaluating either setting. With an NDK Clang driver as
Cargo's linker, pass the two options through target-specific Rust flags, for example: [R1]

```toml
[target.aarch64-linux-android]
rustflags = [
  "-C", "link-arg=-Wl,-z,max-page-size=16384",
  "-C", "link-arg=-Wl,-z,common-page-size=16384",
]
```

The corresponding `x86_64-linux-android` target needs the same two link arguments. If `ld.lld` is
ever invoked directly instead of through Clang, use the linker-native forms
`-z max-page-size=16384` and `-z common-page-size=16384`; `-Wl,` is Clang-driver syntax.

The release verifier, not the presence of flags in a command, is authoritative. For every accepted
non-empty `PT_LOAD` program header, require:

1. `p_align` is a power of two and is at least `16384` (`2**14`);
2. `p_offset % p_align == p_vaddr % p_align`;
3. the existing file-size, memory-size, overflow, file-bound, and executable-entry checks continue
   to pass.

Accept larger power-of-two alignments such as 64 KiB. Reject `0`, `1`, 4 KiB, and 8 KiB alignment
for a non-empty load segment. A hostile fixture must include one under-aligned `PT_LOAD` among
otherwise compliant segments, so an implementation that checks only the first segment fails its
test.

## What the official sources require

### Current Android application guidance

The current Android guide states: "NDK version r28 and higher compile 16 KB-aligned by default."
Its r27-and-lower section then says to use both:

```text
-Wl,-z,max-page-size=16384
-Wl,-z,common-page-size=16384
```

The same page gives those two options in both its ndk-build `LOCAL_LDFLAGS` and CMake
`target_link_options` examples. It also warns that every prebuilt shared library must be rebuilt
and reimported with 16 KiB alignment. [A1]

For verification, the guide runs `llvm-objdump -p FILE.so` and shows every `LOAD` line with
`align 2**14`. Its acceptance wording is exact: "ensure that the load segments don't have values
less than `2**14`"; any `2**13`, `2**12`, or lower value requires recompilation. [A1]

This establishes an at-least-16-KiB rule, not an exactly-16-KiB rule. It also establishes that the
inspection applies to the load segments collectively, not merely the first one.

### Exact r27d behavior

The r27d Build System Maintainers Guide says all of the following: [N1]

- "the default configuration for NDK r27 remains 4KiB page sizes";
- 16 KiB-compatible binaries also run on 4 KiB devices, so separate variants are unnecessary;
- build systems must set `-Wl,-z,max-page-size=16384` when linking `arm64-v8a` or `x86_64`;
- C/C++ compilation should define `__BIONIC_NO_PAGE_SIZE_MACRO`, because code must query the
  runtime page size rather than use a build-time `PAGE_SIZE` constant.

The implementation confirms that these are opt-in build-system policies:

- r27d CMake's `flags.cmake` checks `ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES`; when true it adds
  `-D__BIONIC_NO_PAGE_SIZE_MACRO`, and for `arm64-v8a`/`x86_64` it adds only
  `-Wl,-z,max-page-size=16384`. [N2]
- r27d ndk-build's `build-binary.mk` does the equivalent under
  `APP_SUPPORT_FLEXIBLE_PAGE_SIZES=true`, again adding only the max-page-size link option. [N3]

The difference between the old r27d helper implementation and the current Android guide is
material: a raw Cargo link should follow the current guide and pass **both** options explicitly.
Setting either build-system variable in the environment is not a substitute.

`__BIONIC_NO_PAGE_SIZE_MACRO` is a separate source-compatibility control, not an ELF alignment
flag. Pure Rust code does not consume Bionic C headers, but any C/C++ code compiled by a dependency
or build script should receive the define and use `getpagesize()`/`sysconf(_SC_PAGESIZE)` where page
size affects system calls. Final ELF verification is still required after all Rust and native
objects have been linked.

### Why both LLD values are explicit

LLVM LLD describes `maxPageSize` as the maximum page size on which an output can run and says that
"all important alignment decisions must use this value." It parses `-z max-page-size=` with a
target-specific default. LLD separately parses `-z common-page-size=`; that value cannot exceed the
maximum and is used for page-size-related optimizations. [L1]

NDK r27's documented 4 KiB default therefore remains in force when no option is passed. The
current Android guide, rather than an assumed linker default, is the reason Flux should set both
values to 16384 on r27.

## Runtime and verifier criterion

Android Bionic's current ELF loader computes alignment across `PT_LOAD` headers. In
`CheckProgramHeaderAlignment`, it initializes `min_align_` to the runtime page size, visits every
`PT_LOAD`, and lowers `min_align_` for each power-of-two `p_align > 1`. In `LoadSegments`, a system
whose page size is at least 16384 rejects the ELF when `min_align_` is smaller than the system page
size, unless Android's compatibility mode is active. Its diagnostic is "program alignment ...
cannot be smaller than system page size". [B1]

Two consequences matter for Flux:

1. a single 4 KiB- or 8 KiB-aligned load segment can make an otherwise 16 KiB-aligned ELF fail;
2. Android compatibility mode is a fallback for legacy applications, not evidence that Flux
   produced a compatible release artifact, so the static gate must not waive the criterion.

Strictly, the Bionic loop does not exclude a `PT_LOAD` based on `p_filesz` or `p_memsz`, while the
planned Flux rule is phrased for non-empty segments. Flux's current ELF validator already rejects
an empty `PT_LOAD`, so the narrower wording creates no bypass today. If the validator ever permits
empty load headers, their alignment should also be checked to mirror Android's loader and the
guide's "load segments" wording.

The AOSP `check_elf_alignment.sh` helper is not sufficient as Flux's structural verifier. Its
current implementation pipes `objdump` output through `head -1`, so it classifies only the first
`LOAD` alignment even though its regex accepts any exponent of 14 or greater. [S1] The Android
guide's direct-tool instructions are stronger and require inspection of all `LOAD` lines. Parsing
the ELF program-header table in `xtask` avoids this first-segment blind spot and avoids depending
on output formatting.

## Verification boundary

Static release checks should cover every separately shipped Android ELF, after the final link and
before packaging. A successful 4 KiB WSA run is useful functional evidence but cannot prove 16 KiB
runtime compatibility. The Android guide requires a 16 KiB test environment and uses
`adb shell getconf PAGE_SIZE`, expecting `16384`, before runtime testing. [A1]

APK zip alignment is a different layer. For an APK with uncompressed native libraries, Android's
guide additionally requires Build-Tools 35 or newer and checks the package with:

```text
zipalign -c -P 16 -v 4 APK_NAME.apk
```

That command does not replace ELF `PT_LOAD` inspection. It is out of scope for the current raw
Magisk-module artifact, but becomes mandatory if Flux later ships the same binaries inside an APK
without extracting its native libraries. [A1]

## Implementation acceptance checklist

- Apply both link arguments to every final Android AArch64 and x86_64 Cargo link under NDK r27d.
- Inspect the real Cargo command environment in a regression so the arguments cannot silently drop
  out of the `xtask` path.
- Extend the existing structured ELF parser; do not shell out to `objdump` for the release decision.
- Test a compliant 16 KiB fixture, a 64 KiB fixture, 4 KiB and 8 KiB fixtures, and a multi-load
  fixture whose later segment alone is under-aligned.
- Retain the existing congruence, bounds, overflow, entry-point, and non-empty-segment checks.
- Cross-build the real AArch64 release artifact and inspect every `PT_LOAD` after final linking.
- Record WSA as x86_64/4 KiB functional evidence only; keep physical or virtual 16 KiB Android
  runtime evidence as a separate gate.

## Primary sources

- **[A1] Android Developers, "Support 16 KB page sizes"** (current guide, accessed 2026-07-26):
  <https://developer.android.com/guide/practices/page-sizes>
- **[A2] Android Developers, NDK downloads** (identifies r27d as `27.3.13750724`, accessed
  2026-07-26): <https://developer.android.com/ndk/downloads#lts-downloads>
- **[N1] NDK r27d Build System Maintainers Guide, "Page sizes"** (immutable r27d commit):
  <https://android.googlesource.com/platform/ndk/+/13447502af3f446b0010f618b52ea18819b3dfb5/docs/BuildSystemMaintainers.md#Page-sizes>
- **[N2] NDK r27d CMake flexible-page-size implementation** (lines 35-40):
  <https://android.googlesource.com/platform/ndk/+/13447502af3f446b0010f618b52ea18819b3dfb5/build/cmake/flags.cmake#35>
- **[N3] NDK r27d ndk-build flexible-page-size implementation** (lines 135-140):
  <https://android.googlesource.com/platform/ndk/+/13447502af3f446b0010f618b52ea18819b3dfb5/build/core/build-binary.mk#135>
- **[L1] LLVM LLD 18.1.8 ELF driver** (`getMaxPageSize`, `getCommonPageSize`, and configuration
  comments):
  <https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/lld/ELF/Driver.cpp#L1923-L1957>
  and
  <https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/lld/ELF/Driver.cpp#L2964-L2974>
- **[B1] AOSP Bionic ELF loader** (current main pinned at
  `731631f300090436d7f5df80d50b6275c8c60a93`, alignment collection and rejection):
  <https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/linker/linker_phdr.cpp#541>
  and
  <https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/linker/linker_phdr.cpp#971>
- **[S1] AOSP `check_elf_alignment.sh`** (current main pinned at
  `fc2494a2abd7ab21774d03deb09c1362bbb0bba8`, first-`LOAD` test at lines 99-105):
  <https://android.googlesource.com/platform/system/extras/+/fc2494a2abd7ab21774d03deb09c1362bbb0bba8/tools/check_elf_alignment.sh#99>
- **[R1] Cargo target-specific linker and `rustflags` configuration**:
  <https://doc.rust-lang.org/cargo/reference/config.html#targettriplerustflags>
  and <https://doc.rust-lang.org/cargo/reference/config.html#targettriplelinker>
