#!/usr/bin/env bash
#
# mockenv.sh - deterministic stand-ins for the Linux tools that vps-audit.sh
# probes. Source this file, then run `bash vps-audit.sh`; the exported shell
# functions shadow the real commands so the audit runs offline, fast, and
# produces byte-identical findings on every machine and every run.
#
# vps-audit.sh is NOT modified. We only control its environment.
#
# The scenario is deliberately engineered to reproduce the known
# "Intrusion Prevention" triple-emission: docker is present but inactive and
# neither fail2ban nor crowdsec is installed as a package, which makes the
# audit emit that one check three times (WARN, WARN, FAIL).
#
# Commands intentionally NOT mocked:
#   apt-get  -> absent on the test host; the script's own fallback sets
#               UPDATES=0 (a deterministic PASS), so no stub is needed.
#
# Note: netstat IS shadowed even though it is "Linux-ish" because Windows ships
# a real netstat.exe that command -v finds; without a stub the script would run
# the Windows binary and the port check would misfire.

export HOSTNAME="audit-test-host"

uname()    { echo "6.1.0-test"; }
hostname() { echo "audit-test-host"; }
nproc()    { echo "2"; }
curl()     { echo "203.0.113.10"; }   # never touch the network
find()     { return 0; }              # no '/' traversal; reports 0 SUID files
sysctl()   { echo "1024"; }           # net.ipv4.ip_unprivileged_port_start
lscpu()    { echo "Model name: Test CPU @ 2.0GHz"; }
ufw()      { echo "Status: active"; } # -> Firewall (UFW) PASS
docker()   { return 0; }              # presence matters; body unused on the inactive path

uptime() {
    case "${1:-}" in
        -p) echo "up 1 hour" ;;
        -s) echo "2026-06-15 00:00:00" ;;
        *)  echo " 00:00:00 up 1 hour,  1 user,  load average: 0.10, 0.20, 0.30" ;;
    esac
}

free() {
    if [ "${1:-}" = "-h" ]; then
        printf '%s\n' \
            "              total        used        free      shared  buff/cache   available" \
            "Mem:           4.0G        1.0G        2.5G          0        0.5G        2.8G"
    else
        printf '%s\n' \
            "              total        used        free      shared  buff/cache   available" \
            "Mem:        4000000     1000000     2500000           0      500000     2800000"
    fi
}

df() {
    printf '%s\n' \
        "Filesystem      Size  Used Avail Use% Mounted on" \
        "/dev/root        40G   12G   26G  30% /"
}

top() {
    echo "%Cpu(s):  5.0 us,  1.0 sy,  0.0 ni, 93.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st"
}

netstat() {
    # Linux-style `netstat -tuln`; the script reads the address from field 4.
    printf '%s\n' \
        "Proto Recv-Q Send-Q Local-Address     Foreign-Address   State" \
        "tcp        0      0 0.0.0.0:22        0.0.0.0:*         LISTEN" \
        "tcp        0      0 0.0.0.0:80        0.0.0.0:*         LISTEN"
}

ss() {
    # Fallback for hosts without netstat; the script reads field 5 here.
    printf '%s\n' \
        "Netid State  Recv-Q Send-Q Local-Address:Port Peer-Address:Port" \
        "tcp   LISTEN 0      0      0.0.0.0:22         0.0.0.0:*" \
        "tcp   LISTEN 0      0      0.0.0.0:80         0.0.0.0:*"
}

systemctl() {
    case "${1:-}" in
        is-active)  return 1 ;;        # all units inactive -> docker-not-running path
        list-units)
            printf '%s\n' \
                "a.service loaded active running A" \
                "b.service loaded active running B" \
                "c.service loaded active running C" \
                "d.service loaded active running D" \
                "e.service loaded active running E" ;;
        *) return 0 ;;
    esac
}

dpkg() {
    # Only `dpkg -l` is consumed (piped to grep). Include unattended-upgrades
    # (-> PASS) but deliberately OMIT fail2ban and crowdsec so the Intrusion
    # Prevention check resolves through the docker branch.
    printf '%s\n' \
        "ii  unattended-upgrades  2.8    all   automatic security updates" \
        "ii  bash                 5.1    amd64 GNU Bourne Again SHell"
}

export -f uname hostname nproc curl find sysctl lscpu ufw docker \
          uptime free df top netstat ss systemctl dpkg
