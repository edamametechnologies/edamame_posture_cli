#!/usr/bin/env python3
"""
Trigger the DNS-tunnel exfiltration shape (blind spot BS-6/BS-5).

Holds sensitive credential files open while streaming a sustained,
high-volume run of DNS-shaped UDP datagrams to a public resolver on
port 53. Historically invisible: udp/53 was unconditionally classified
as a routine destination, so `token_exfiltration`'s deterministic
sustained-sensitive-egress path never fired. The CloudModel gate
`treat_high_volume_dns_ntp_as_non_routine` (with its
`dns_ntp_non_routine_min_outbound_bytes` floor) closes that; this
scenario proves the gate end to end.

Detection path (no anomaly flag required):
  s