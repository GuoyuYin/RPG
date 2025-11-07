# CSGO: A configuration sensitived kernel fuzzer

CSGO is a Config-Sensitived kernel fuzzer wirtten in GOlang. It can consider thousands of runtime configuration knobs that live in /proc/sys and /sys as fuzzing inputs.  Instead of hammering the Linux kernel only with syscall sequences, as Syzkaller and its derivatives do, CSGO automatically boots the kernel once, harvests every writable parameter, infers its type and legal range, and then synthesises “configuration calls” that can tweak those parameters on the fly.  A static analysis links each configuration to the subsystems targeted by specific syscalls, seeding a weight table that is continuously refined at run time: whenever a particular config-plus-syscall pair unlocks new coverage, its weight is boosted so the fuzzer leans harder on that combination in future iterations.

## How to Use CSGO

To build CSGO, run
```bash 
make -j
```

To start the fuzzing process, run

```bash
./bin/syz-manager -config config.json
```

where config.json is the start script, should assign workdir, kernel image / source code path /  relation matrix path

```json
{
	"target": "linux/amd64",
	"http": "127.0.0.1:56741",
	"workdir": "/path/to/workdir-new",
	"kernel_obj": "/path/to/linux",
	"image": "/path/to/bullseye.img",
	"sshkey": "/path/to/bullseye.id_rsa",
	"priority_table": "/path/to/relation_matrix.csv",
	"syzkaller": "./",
	"procs": 8,
	"type": "qemu",
	"vm": {
		"count": 8,
		"kernel": "/path/to/bzImage",
		"cpu": 4,
		"mem": 4096
	}
}
```