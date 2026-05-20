#!/bin/bash

# Linux Persistence detection and artifact hunting script

set +e  # Continue on errors

SUS_KEYWORDS_REGEX="curl |wget |nc -|ncat |socat |python([23]?) -c|perl -e|/tmp/|/var/tmp/|/dev/shm/|/dev/tcp/|/dev/udp/|/home/|.*/\..*"

print_header() {
  # $1: Check name
  local name="$1"
  echo ""
  echo "=== $name ==="
}

# --- Main ---

# System information
print_header "[SYSTEM] System Information"
uname -a 2>/dev/null
cat /etc/os-release 2>/dev/null

# High-confidence: AT Job Persistence
# Legit 'at' jobs are uncommon, an unexpected 'at' entry is highly suspicious
print_header "[HIGH] AT job files present in /var/spool/at/"
atq 2>/dev/null
ls -la /var/spool/at/ 2>/dev/null

# High-confidence: Cron entry referencing a suspicious keyword
print_header "[HIGH] Cron entry referencing a suspicious keyword"
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/*; do
  if [[ -f "$f" ]]; then
    grep -E "$SUS_KEYWORDS_REGEX" "$f" 2>/dev/null | while read -r line; do
      [[ ! "$line" =~ ^# ]] && echo "$f: $line";
    done
  fi
done

# High-confidence: Active Bind Shell
# Look for interpreter processes (like bash/sh/python) listening on network socket
print_header "[HIGH] Active bind shell"
ss -lptnH 2>/dev/null 2>/dev/null | while read -r conn_line; do
  conn=$(echo "$conn_line" | awk '{print $4" "$5" "$6}')
  proc=$(echo "$conn" | awk '{print $3}');
  if [[ -n "$proc" ]]; then
    pid=$(echo "$proc" | awk -F 'pid=' '{print $2}' | awk -F ',' '{print $1}')
    exe=$(cat /proc/$pid/comm 2>/dev/null)
    case "$exe" in
      bash|sh|zsh|dash|ksh|python*|perl|nc|ncat|socat)
      [[ -n "$exe" ]] && echo "$conn_line"
      [[ -n "$exe" ]] && echo "$(ps auxww | grep $pid | grep -v grep)"
      ;;
    esac
  fi
done

# High-confidence: Active Reverse Shell
# Look for processes that have stdin and stdout redirected to a socket
print_header "[HIGH] Active reverse shell"
ps aux 2>/dev/null | while read -r ps_line; do
  pid=$(echo "$ps_line" | awk '{print $2}')
  if [[ -n "$$pid" ]]; then
    exe=$(cat /proc/$pid/comm 2>/dev/null)
    case "$exe" in
      bash|sh|zsh|dash|ksh|python*|perl|nc|ncat|socat)
      stdin=$(ls -l /proc/$pid/fd/0 | grep socket)
      stdout=$(ls -l /proc/$pid/fd/1 | grep socket)
      if [[ -n "$stdin" && -n "$stdout" ]]; then
        [[ -n "$exe" ]] && echo "$ps_line"
      fi
      ;;
    esac
  fi
done

# High-confidence: Persistence using eBPF with raw network socket
# Rootkits such as BPFdoor use eBPF programs with raw network sockets for persistent backdoor
print_header "[HIGH] eBPF programs with raw network sockets (possible BPFdoor persistence)"
egrep packet_recvmsg /proc/*/stack 2>/dev/null | while read -r line; do
  pid=$(echo "$line" | awk -F '/proc/' '{print $2}' | awk -F '/' '{print $1}')
  exe=$(cat /proc/$pid/comm 2>/dev/null)
  if [[ -n "$exe" ]]; then
    echo "PID: $pid, Executable: $exe, Stack trace: $line"
  fi
done

# High-confidence: Systemd service/timer referencing a suspicious keyword
# Look for .service and .timer files under known paths that contains */systemd/*
# Includes system-level and any user-level systemd units under ~/.config/systemd/user/
print_header "[HIGH] Systemd service/timer referencing a suspicious keyword"
find /etc /lib /usr /run /home/*/.config -path '*/systemd/*' -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null | xargs grep -EH "$SUS_KEYWORDS_REGEX" 2>/dev/null

# High-confidence: Init/rc.local script referencing a suspicious keyword
print_header "[HIGH] Init/rc.local/profile script referencing a suspicious keyword"
find /etc/init.d /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/rc.local -type f 2>/dev/null | xargs grep -EH "$SUS_KEYWORDS_REGEX" 2>/dev/null

# High-confidence: MOTD script referencing a suspicious keyword
print_header "[HIGH] MOTD script referencing a suspicious keyword"
find /etc/motd /etc/update-motd.d/ -type f 2>/dev/null | xargs grep -EH "$SUS_KEYWORDS_REGEX" 2>/dev/null

# High-confidence: Shell profile referencing a suspicious keyword
print_header "[HIGH] Shell profile referencing a suspicious keyword"
for f in /etc/profile /etc/profile.d/* /root/.bash_profile /root/.bashrc /root/.profile /root/.bash_login /home/*/.bash_profile /home/*/.bashrc /home/*/.profile /home/*/.bash_login; do
  if [[ -f "$f" ]]; then
    grep -E "$SUS_KEYWORDS_REGEX" "$f" 2>/dev/null | while read -r line; do
      [[ ! "$line" =~ ^# ]] && echo "$f: $line";
    done
  fi
done

# High-confidence: D-BUS service files referencing a suspicious keyword
print_header "[HIGH] D-BUS service files referencing a suspicious keyword"
find  / -path */dbus-1/* -type f -name '*.service' 2>/dev/null | xargs grep -EH "$SUS_KEYWORDS_REGEX" 2>/dev/null

# High-confidence: NetworkManager dispatcher scripts referencing a suspicious keyword
print_header "[HIGH] NetworkManager dispatcher scripts referencing a suspicious keyword"
find  / -path */NetworkManager/dispatcher.d/* -type f -executable 2>/dev/null | xargs grep -EH "$SUS_KEYWORDS_REGEX" 2>/dev/null

# High-confidence: Dotfiles in home directories (possible agent configs/binaries)
print_header "[HIGH] Hidden ELF executable files in tmp/home/hidden dirs"
find /tmp /var/tmp /home /dev/shm/ -type f -name ".*" 2>/dev/null | while read -r f; do
  [[ -f "$f" ]] && file "$f" | grep -q 'ELF' && echo "$f";
done

# High-confidence: Running processes referencing a suspicious keyword
print_header "[HIGH] Running processes referencing a suspicious keyword"
ps auxww | grep -v grep | grep -E "$SUS_KEYWORDS_REGEX" | while read -r line; do
  echo "$line";
done

# High-confidence: World-writable SUID/SGID binaries
# Look for world-writable files that have SUID or SGID or both permissions set
print_header "[HIGH] SUID/SGID/world-writable ELF binary"
find / -type f \( -perm /6000 -a -perm /0002 \) 2>/dev/null | while read -r f; do
  file "$f" | grep -q 'ELF' && echo "$f";
done

# High-confidence: Hidden Processes (possible rootkit)
# Rootkits such as Diamorphine can hide processes from ps output by backdooring
# syscalls such as getdents.
#
# We can detect such processes by brute-forcing /proc for all possible PIDs and
# compare against ps output.
#
# We can test this code by installing a rootkit such as Diamorphine or alternatively
# by temporarily backdooring the ps binary in a controlled environment.
#
# To hide PID 1234:
# mv /usr/bin/ps /usr/bin/ps.orig
# echo '/usr/bin/ps.orig "$@" | grep -v 1234' > /usr/bin/ps
print_header "[HIGH] Hidden process detected in /proc (possible rootkit)"
pid_max=$(cat /proc/sys/kernel/pid_max 2>/dev/null)
[[ -z "$pid_max" ]] && pid_max=4194304
for pid in $(seq 1 "$pid_max"); do
  status_file="/proc/$pid/status"
  if [[ -f "$status_file" ]]; then
    tgid=$(awk '/^Tgid:/ {print $2}' "$status_file" 2>/dev/null)
    # Only check main process, not threads
    if [[ "$tgid" == "$pid" ]]; then
      if ! ps --no-headers -p "$pid" > /dev/null 2>&1; then
        exe=""
        cmdline=""
        [[ -e "/proc/$pid/exe" ]] && exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        [[ -e "/proc/$pid/cmdline" ]] && cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        echo "PID $pid"
        [[ -n "$exe" ]] && echo "Executable: $exe"
        [[ -n "$cmdline" ]] && echo "Cmdline: $cmdline"
      fi
    fi
  fi
done

# High-confidence: Hidden Process (/proc bind mount trick)
# "mount -o bind mydir /proc/1234" essentially makes /proc/1234 dir invisible
# So PID 1234 will not show up in ps output but the process is still running
# Any mounts involving /proc are highly suspicious
print_header "[HIGH] Hidden process with bind mount trick"
mount -l | grep -E "/proc/[0-9]+" 2>/dev/null

# High-confidence: System wide LD_PRELOAD
# Rootkits abuse /etc/ld.so.preload for persistence
print_header "[HIGH] LD_PRELOAD configured system wide"
if [ -f "/etc/ld.so.preload" ]; then
  stat /etc/ld.so.preload
fi

# Low-confidence: Files with capabilities
print_header "[LOW] Files with capabilities"
getcap -r / 2>/dev/null

# Low-confidence: Any recent (7 days) ELF binary in tmp/home/hidden dirs
print_header "[LOW] Recent ELF binary in tmp/home/hidden dirs"
find /tmp /var/tmp /dev/shm /home/* -type f -executable -mtime -7 2>/dev/null | while read -r f; do
  file "$f" | grep -q 'ELF' && echo "$f";
done

# Low-confidence: git config and hooks files
print_header "[LOW] Git config or hooks file"
find / -type f \( -path '*/.git/config' -o -path '*/.git/hooks/*' \) ! -name '*.sample' 2>/dev/null | while read -r f; do
  [[ -n "$f" ]] && echo "$f";
done

# Low-confidence: APT hooks referencing a suspicious keyword
print_header "[LOW] APT hooks referencing a suspicious keyword"
find /etc/apt/apt.conf.d/ -type f 2>/dev/null | xargs grep -EH 'DPkg::Post-Invoke|APT::Update::Pre-Invoke' 2>/dev/null

# Low-confidence: Yum/DNF plugins referencing a suspicious keyword
print_header "[LOW] Yum/DNF plugins referencing a suspicious keyword"
find /usr/lib/yum-plugins/ /usr/lib/python*/site-packages/dnf-plugins/ -type f -name '*.py' 2>/dev/null | xargs grep -EH "$SUS_KEYWORDS_REGEX" 2>/dev/null

# Low-confidence: .pth file persistence in Python modules
# Lines in .pth files beginning with the keyword import followed by a space or a tab are executed when the module is imported
print_header "[LOW] .pth file with suspicious content (Python persistence)"
find /usr/lib/python* /usr/local/lib/python* /home/*/.local/lib/python* -type f -name '*.pth' 2>/dev/null | while read -r f; do
  line=$(grep -EH 'import |os\.system|exec\(' "$f" 2>/dev/null)
  if [[ -n "$line" ]]; then
    echo "$line";
  fi
done

# Low-confidence: Udev rules with RUN key
print_header "[LOW] Udev rules with RUN key (possible persistence)"
find / -path */udev/rules.d/* -type f -name *.rules -exec grep -iH "run+=" {} \; 2>/dev/null

# Low-confidence: PAM modules with suspicious content
print_header "[LOW] PAM module with suspicious content"
grep -iH pam_exec /etc/pam.d/* 2>/dev/null

# Low-confidence: Recent modified binary files in /usr/bin, /usr/local/bin, /bin, /sbin
# Hijacking system binaries
print_header "[LOW] Recent modified binary files in common bin dirs"
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin/ -type f -executable -mtime -7 2>/dev/null

# Informational: Print all cron entries and their content
print_header "[INFORMATIONAL] All cron entries (manual review)"
find /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* -type f 2>/dev/null | while read -r f; do
  echo "--- $f ---"
  cat "$f" | grep -v '^#' 2>/dev/null
  echo ""
done

# Informational: Print all shell profiles
print_header "[INFORMATIONAL] All shell profiles (manual review)"
for f in /etc/profile /etc/profile.d/* /root/.bash_profile /root/.bashrc /root/.profile /root/.bash_login /home/*/.bash_profile /home/*/.bashrc /home/*/.profile /home/*/.bash_login; do
  if [[ -f "$f" ]]; then
    echo "--- $f ---"
    cat "$f" | grep -v '^#' 2>/dev/null
    echo ""
  fi
done

# Informational: Print all init.d and rc.local scripts
print_header "[INFORMATIONAL] All init.d and rc.local scripts (manual review)"
find /etc/init.d /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/rc.local -type f 2>/dev/null | while read -r f; do
  echo "--- $f ---"
  cat "$f" | grep -v '^#' 2>/dev/null
  echo ""
done

# Informational: Print all MOTD files
print_header "[INFORMATIONAL] All MOTD files (manual review)"
find /etc/motd /etc/update-motd.d/ -type f 2>/dev/null | while read -r f; do
  echo "--- $f ---"
  cat "$f" | grep -v '^#' 2>/dev/null
  echo ""
done

# Informational: List all recent ELF binaries in tmp/home
print_header "[INFORMATIONAL] Recent (7 days) ELF binaries (manual review)"
find /tmp /var/tmp /dev/shm /home/* -type f -executable -mtime -7 2>/dev/null | while read -r f; do
  file "$f" | grep -q 'ELF' && echo "$f"
done

# Informational: List all dotfiles in home directories
print_header "[INFORMATIONAL] List all dotfiles in home directories (manual review)"
for d in /home/*; do
  [[ -d "$d" ]] && find "$d" -maxdepth 1 -type f -name '.*' 2>/dev/null | while read -r f; do
    [[ -n "$f" ]] && echo "$f";
  done
done

# Informational: Print non-empty SSH Authorized keys files in home directories
print_header "[INFORMATIONAL] SSH authorized keys in home directories (manual review)"
find /root /home/ -type f -name 'authorized_keys*' 2>/dev/null | while read -r f; do
  if [[ -s "$f" ]]; then
    echo "--- $f ---"
    cat "$f" | grep -v '^#' 2>/dev/null
    echo ""
  fi
done

# Informational: local users and groups
print_header "[INFORMATIONAL] Local users and groups (manual review)"
getent passwd | while read -r line; do
  [[ -n "$line" ]] && echo "$line";
done
getent group | while read -r line; do
  [[ -n "$line" ]] && echo "$line";
done

# Informational: All mounts
print_header "[INFORMATIONAL] Mounts (manual review)"
mount -l 2>/dev/null

# Informational: Active Network connections
print_header "[INFORMATIONAL] Active Network connections (manual review)"
ss -tunap

# Informational: Systemd services
print_header "[INFORMATIONAL] Systemd services (manual review)"
systemctl list-units --type=service --state=running 2>/dev/null

# Informational: D-BUS service files
print_header "[INFORMATIONAL] D-BUS service files (manual review)"
find  / -path */dbus-1/* -type f -name '*.service' 2>/dev/null | while read -r f; do
  echo "--- $f ---"
  cat "$f" | grep -v '^#' 2>/dev/null
  echo ""
done

# Informational: NetworkManager dispatcher scripts
#
# NetworkManager-dispatcher is a D-Bus activated service
# that runs scripts upon certain changes in NetworkManager.
print_header "[INFORMATIONAL] NetworkManager dispatcher scripts (manual review)"
find  / -path */NetworkManager/dispatcher.d/* -type f -executable 2>/dev/null | while read -r f; do
  echo "--- $f ---"
  cat "$f" | grep -v '^#' 2>/dev/null
  echo ""
done

# Informational: Running containers and images for docker, containerd, podman, etc.
# Docker images and containers
print_header "[INFORMATIONAL] Docker images and running containers (manual review)"
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null
docker ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null

# Podman images and containers
print_header "[INFORMATIONAL] Podman images and running containers (manual review)"
podman images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null
podman ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null

# Containerd containers and images (all namespaces)
print_header "[INFORMATIONAL] Containerd namespaces and containers/images (manual review)"
if command -v ctr &>/dev/null; then
  for ns in $(ctr namespaces list -q 2>/dev/null); do
    echo "Containerd namespace: $ns"
    ctr -n "$ns" images list 2>/dev/null | tail -n +2
    ctr -n "$ns" containers list 2>/dev/null | tail -n +2
  done
fi

# Informational: Installed packages
print_header "[INFORMATIONAL] Installed packages (manual review)"
if command -v dpkg &>/dev/null; then
  dpkg -l --no-pager
elif command -v rpm &>/dev/null; then
  rpm -qa
elif command -v dnf &>/dev/null; then
  dnf list installed
fi

# Informational: Loded kernel modules
print_header "[INFORMATIONAL] Loaded kernel modules (manual review)"
lsmod 2>/dev/null
