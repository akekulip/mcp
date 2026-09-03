#!/bin/bash
# Silicon detection-fidelity sweep v2 on mcp_fabric_ledger (wire-reduction, 2B witness).
# Fixes: (1) use the uncapped exact 'A' injector (drop exactly D stamps) instead of 'S' (254 cap);
# (2) wrap-handle the 16-bit reg_wit_seq delta mod 65536; (3) keep every cell < 65536 packets.
# Per rate regime: arm exactly D drops on sublink 2, send N ctx-2 packets, verify the ledger
# recovers exactly D (Delta_seq_mod - Delta_obs). Clean cell => false-positive rate.
set -u
SW=decps@10.10.54.81; VIS=decps@10.10.54.166; SUB=2; IFACE=enp59s0f0np0

gate() { ssh "$SW" "python3 -c \"
import socket,time
s=socket.create_connection(('127.0.0.1',47100),timeout=8)
s.sendall(b'$1\n'); time.sleep(0.3); print(s.recv(4096).decode().strip()); s.close()
\""; }
read_sub() { gate "R $SUB" | awk -v s="$SUB" '$1=="S" && $2==s {print $5, $6}'; }
probe() { source ~/.lab_env 2>/dev/null
  sshpass -e ssh "$VIS" "sudo /usr/bin/python3 /home/decps/mcp_multicontext_probe.py --iface $IFACE --count $1 --pps $2 --contexts $SUB" 2>&1 | tail -1 >/dev/null; }

run_cell() { # label N D
  local label=$1 N=$2 D=$3
  gate "C" >/dev/null
  local b; b=$(read_sub); local bseq=${b% *} bobs=${b#* }
  local armed="clean"
  [ "$D" -gt 0 ] && armed=$(gate "A $SUB $D")
  probe "$N" 20000
  sleep 1.5
  local a; a=$(read_sub); local aseq=${a% *} aobs=${a#* }
  local dseq=$(( (aseq - bseq + 65536) % 65536 ))   # 16-bit wrap-safe (N<65536)
  local dobs=$(( aobs - bobs ))
  local recovered=$(( dseq - dobs ))
  local rate; rate=$(python3 -c "print(f'{$D/$N:.1e}')")
  printf "%-9s N=%-6s D=%-3s rate=%-7s  Dseq=%-6s Dobs=%-6s  recovered=%-4s  match=%s  [%s]\n" \
    "$label" "$N" "$D" "$rate" "$dseq" "$dobs" "$recovered" \
    "$( [ "$recovered" = "$D" ] && echo YES || echo "NO(exp $D)" )" "${armed:0:24}"
  gate "C" >/dev/null
}

echo "=== SILICON DETECTION-FIDELITY SWEEP v2  ($(date -Is)) ==="
echo "program: mcp_fabric_ledger (wire-reduction 2B); sublink $SUB (vlink0 ctx2); exact 'A' injector"
echo "--- clean (false-positive): expect recovered = 0 ---"
run_cell clean-1 20000 0
echo "--- loss-magnitude sweep: expect recovered = D exactly ---"
run_cell p=1e-2  5000  50
run_cell p=1e-2b 5000  50
run_cell p=1e-3  30000 30
run_cell p=1e-3b 30000 30
run_cell p=5e-4  40000 20
run_cell p=1e-4  60000 6
run_cell p=1e-4b 60000 6
echo "=== done  ($(date -Is)) ==="; gate "C" >/dev/null; echo "injectors cleared."
