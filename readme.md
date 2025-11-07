# CSGO: A configuration sensitived kernel fuzzer

CSGO is a Config-Sensitived kernel fuzzer wirtten in GOlang. It can consider thousands of runtime configuration knobs that live in /proc/sys and /sys as fuzzing inputs.  Instead of hammering the Linux kernel only with syscall sequences, as Syzkaller and its derivatives do, CSGO automatically boots the kernel once, harvests every writable parameter, infers its type and legal range, and then synthesises “configuration calls” that can tweak those parameters on the fly.  A static analysis links each configuration to the subsystems targeted by specific syscalls, seeding a weight table that is continuously refined at run time: whenever a particular config-plus-syscall pair unlocks new coverage, its weight is boosted so the fuzzer leans harder on that combination in future iterations.

## Key Features
- __Configuration-Aware Input Generation.__ Automatically boots the target kernel once, extracts every writable /proc/sys and sysfs parameter, infers its type/range, and synthesises configuration calls that can be mixed with ordinary syscalls. This turns thousands of runtime knobs into fuzzing inputs.
- __Static + Dynamic Mapping Deduction.__ Builds an initial weight table by matching each configuration to the subsystems touched by specific syscalls, then continuously updates that table at run-timeâ€”boosting pairs that unlock new coverage, throttling those that do not.
- __Feedback-Guided Exploration Loop.__ Uses KCOV coverage and KASAN/KCSAN signals to select, mutate, and prioritise inputs; any config + syscall combo that expands coverage gets a higher weight, steering the search toward deep, state-dependent paths.

## Work Trees
- Config-extart directory is used to extract kernel config, and covert the dynamic configuration into system call specifications (Syzlang)
- Relation matrix directory is used to conduct static relation deduction and get the relation matrix
- CSGO directory is the main fuzzer, used to conduct the fuzzing
- open-data contains our evaluation data set

## How to Use

- To use CSGO, first need to prepare a corresponding kernel image, which can be refered from [Syzkaller offical docs](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md) 
- Once kernel is ready, boot it, run content in config extract, to extract dynamic configuration and corresponding syzlang specification.
- Once generated the syzlang specifications host machine, run relation matrix directroy to generate relation matrix 
- After generate relation matrix, start the fuzzing process in CSGO directory
