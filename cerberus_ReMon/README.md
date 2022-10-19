# Cerberus

## Introduction
This repository hosts **Cerberus**, a PKU-based sandboxing framework.

**NOTES:**
- To build Cerberus, we got inspired from **[ReMon](https://github.com/stijn-volckaert/ReMon)**, a secure and efficient Multi-Variant Execution Environment (MVEE) for x86 Linux programs. However, **Cerberus** is independent from **[ReMon](https://github.com/stijn-volckaert/ReMon)** (**Cerberus** is not a modified version of **[ReMon](https://github.com/stijn-volckaert/ReMon)**).

## Cerberus Prerequisites
You will need:
- A GNU/Linux distribution based on Debian. We **_strongly_** recommend Ubuntu 18.04 x64, since we have not (yet) tested any other distribution.
- Ruby
- CMake (>= 3.4.3)
- The Cerberus toolchain, which can be installed using the `bootstrap.sh` script. `bootstrap.sh` also fixes absolute paths in tests and benchmarks.

## Cerberus Instructions

### Building Cerberus

Building Cerberus is really easy. Just navigate to [cerberus_ReMon/](.) and type `make`.
This will build an optimized and statically linked version of the Cerberus binary.

You will find the compiled Cerberus binary (named MVEE) in [MVEE/bin/Release/](./MVEE/bin/Release).
 
### Configuring Cerberus

Cerberus contains a number of configurable options and features. Features that severely impact Cerberus's performance generally must be configured at compile time by editing [MVEE/Inc/MVEE_build_config.h](./MVEE/Inc/MVEE_build_config.h). Don't forget to recompile Cerberus after editing that.

A feature that you might want to use is **debug logging**. Debugging logging can be enabled by disabling the `MVEE_BENCHMARK` feature in [MVEE/Inc/MVEE_build_config.h](./MVEE/Inc/MVEE_build_config.h) (by default disabled). 

Other features that you may want to enable are the kernel PKU sandbox and the cross-process sandbox in [MVEE/Inc/MVEE_build_config.h](./MVEE/Inc/MVEE_build_config.h) (by default enabled).
- `MVEE_CERBERUS_CP_PKU_SANDBOX_ENABLED`: Enables the cross-process sandbox.
- `MVEE_CERBERUS_KERNEL_PKU_SANDBOX_ENABLED`: Enables the kernel sandbox that speeds up Cerberus and denies opening of sensitive files (requires a custom kernel).
- `ENABLE_ERIM_POLICY` and `ENABLE_XOM_SWITCH_POLICY` are the policies that we used in our [EuroSys 2022 paper](https://alexios-voulimeneas.github.io/papers/cerberus.pdf).

**Notes for ERIM rewritten binaries**
- Enable `MVEE_DYNINST_BUGS_TREAT` in [MVEE/Inc/MVEE_build_config.h](./MVEE/Inc/MVEE_build_config.h) and recompile.
- Set `use_erim_binary_rewriting_libs` to `true` in [MVEE.ini](./MVEE/bin/Release/MVEE.ini).

### Running Cerberus

You'll find the Cerberus binary (called MVEE) in [MVEE/bin/Release/](./MVEE/bin/Release).

You can launch Cerberus doing the following:
- `./MVEE -N 1 -- "[Program] [Additional Program Args]"`
- e.g., `./MVEE -N 1 -- "ls"` and `./MVEE -N 1 -- "echo test"`

**NOTES:**
- Check [benchmarks](./benchmarks) folder to replicate the experiments of our [EuroSys 2022 paper](https://alexios-voulimeneas.github.io/papers/cerberus.pdf).

### Shutting Cerberus down

The easiest way to shut Cerberus down is to use CTRL+C.

### Building Cerberus custom kernel

**Cerberus kernel PKU sandbox** requires some kernel modifications to run. Cerberus ships with the necessary kernel patch for Linux 5.3.

Before doing anything else, we need to enable Sources in Software and Updates. Then use the following commands to build and install the custom kernel:
<!--- alternatively use make localmodconfig -->
<!--- The following command is useful in case that we want to use localmodconfig cp /boot/config-5.3.0-66-generic .config -->

	sudo apt-get update
	sudo apt-get install linux-source-5.3.0
	tar jxf /usr/src/linux-source-5.3.0/linux-source-5.3.0.tar.bz2
	cd linux-source-5.3.0
	patch -p1 < path/to/cerberus_ReMon/patches/linux-5.3.0-full-cerberus.patch
	make menuconfig
	scripts/config --disable DEBUG_INFO
	scripts/config --disable CONFIG_SYSTEM_TRUSTED_KEYS
	make -j `getconf _NPROCESSORS_ONLN` deb-pkg LOCALVERSION=-cerberus
	sudo dpkg -i ../linux-headers*.deb ../linux-image*.deb ../linux-libc-dev*.deb

**NOTES:**
- It would be useful to make grub menu visible (to be able to easily choose the custom kernel) using the following commands:
```
sudo vi /etc/default/grub
# find the line that says GRUB_TIMEOUT_STYLE and add GRUB_TIMEOUT_STYLE=menu 
# find the line that says GRUB_TIMEOUT and add GRUB_TIMEOUT=10
sudo update-grub
sudo reboot
```

- It is easy to remove the custom kernel using the following commands (linux-image-5.3.18-cerberus refers to the custom kernel):
```
sudo apt-get remove --purge linux-image-5.3.18-cerberus
```

### Cerberus optimized ld.so and libc.so

We have provided Cerberus optimized ld.so and libc.so in [patched_binaries](./patched_binaries).

**NOTES:**
- We can use the default ld.so and libc.so. This is just an optimization.
- [glibc-2.27-cerberus-minimal.patch](./patches/glibc-2.27-cerberus-minimal.patch) can be applied over vanilla glibc to create your own version of Cerberus optimized ld.so and libc.so.
- We applied [glibc-2.27-cerberus-minimal.patch](./patches/glibc-2.27-cerberus-minimal.patch) to Ubuntu 18.04 vanilla glibc. To get the source do `sudo apt-get install -y glibc-source` and then `tar -xf /usr/src/glibc/glibc-2.27.tar.xz`.

# Todo's and minor differences with our EuroSys 2022 paper

- Handlers for a couple of system calls like `mremap`, `process_vm*` should be added (these system calls do not appear in the benchmarks of our [EuroSys 2022 paper](https://alexios-voulimeneas.github.io/papers/cerberus.pdf))
- Move full integration of ReMon's [emulation engine](https://github.com/ReMon-MVEE/ReMon/tree/master/MVEE/Src/arch/amd64/shared_mem) to the public repo (emulation was not needed for the benchmarks of our [EuroSys 2022 paper](https://alexios-voulimeneas.github.io/papers/cerberus.pdf))
- The current version of Cerberus uses a technique similar to [Jenny paper](https://www.usenix.org/system/files/sec22summer_schrammel.pdf) for protecting against attacks that target `Mappings with mutable backings`. This is different compared to the technique described in our [EuroSys 2022 paper](https://alexios-voulimeneas.github.io/papers/cerberus.pdf), but it has the same effects.

## Licenses

- Cerberus is available under the licensing terms in `../LICENSE.md`.
- Code in [benchmarks](./benchmarks) is available under the licensing terms of the corresponding project.
