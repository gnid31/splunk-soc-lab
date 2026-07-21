#!/bin/bash
# SOC Lab Atomic Tests — Linux
# Run on linux-ep-01 with sudo. Logs to /var/log/soclab-atomic.log.
set +e

log=/var/log/soclab-atomic.log
say() { echo "$(date '+%Y-%m-%d %H:%M:%S') [$(hostname)] $*" | tee -a "$log"; }

say "=== ATOMIC TESTS START ==="

# --- T1110 - SSH brute force (15 failed attempts against localhost) ---
say "T1110 start: 15 failed SSH attempts"
for i in $(seq 1 15); do
    sshpass -p "wrong-$i" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o PreferredAuthentications=password -o PubkeyAuthentication=no fakeuser@127.0.0.1 exit 2>/dev/null || true
done
say "T1110 done"

# --- T1071.001 - HTTP beaconing simulation (10 curls to public IP, 30s intervals) ---
say "T1071.001 start: HTTP beacon x10"
for i in $(seq 1 10); do
    curl -s -o /dev/null --max-time 3 "http://93.184.216.34/beacon?i=$i" &
    sleep 30
done
wait
say "T1071.001 done"

# --- T1098 - Account manipulation (add + delete test user) ---
say "T1098 start: useradd + userdel"
useradd -m soclab_atomic_user 2>/dev/null || true
sleep 1
userdel -r soclab_atomic_user 2>/dev/null || true
say "T1098 done"

# --- T1136.001 - Local account creation (repeat under different flag) ---
say "T1136.001 start: create + immediately delete"
useradd soclab_temp 2>/dev/null || true
userdel soclab_temp 2>/dev/null || true
say "T1136.001 done"

# --- T1070.002 - Log tampering (touch, do not truncate) ---
say "T1070.002 start: touch /var/log/audit/audit.log"
touch /var/log/audit/audit.log 2>/dev/null || true
say "T1070.002 done"

say "=== ATOMIC TESTS COMPLETE ==="
tail -30 "$log"
