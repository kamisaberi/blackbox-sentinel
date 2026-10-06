#!/usr/bin/env python3
"""
Aryorithm Commercial License Issuer
Signs a tamper-proof JSON license envelope using the Ed25519 master private key.
"""

import os
import sys
import json
import time
import base64
import argparse
from cryptography.hazmat.primitives.asymmetric import ed25519

KEY_DIR = os.path.dirname(os.path.abspath(__file__))

ALL_26_MODULES = [
    "01_siem_core", "02_ueba", "03_ndr", "04_ids_ips", "05_waf", "06_edr",
    "07_epp_ngav", "08_nac", "09_cwpp", "10_bad", "11_rasp", "12_itdr",
    "13_ddos", "14_ato", "15_ngfw", "16_cdr", "17_iot_sec", "18_cps_sec",
    "19_swg", "20_fse", "21_side_channel", "22_dfir", "23_ai_trism",
    "24_ztna", "25_fdp", "26_ddp"
]

ALL_30_PLUGINS = [
    "libmodbus_dissector.so", "libdnp3_dissector.so", "libs7comm_dissector.so",
    "libprofinet_dissector.so", "libethernet_ip.so", "libhart_ip.so",
    "libmitsubishi_melsec.so", "libomron_fins.so", "libiec104_dissector.so",
    "libiec61850_goose.so", "libiec61850_mms.so", "libopc_ua_dissector.so",
    "libbacnet_building.so", "libmodbus_rtu_serial.so", "libenip_cip.so",
    "libfieldbus_h1.so", "libmavlink_uav.so", "libais_maritime.so",
    "libnmea_gps.so", "libadsb_avionics.so", "libstanag_4586.so",
    "libmil_std_1553.so", "libcanbus_automotive.so", "libdicom_pacs.so",
    "libhl7_v2.so", "libcef_forwarder.so", "libleef_forwarder.so",
    "libsyslog_rfc5424.so", "libkafka_producer.so", "libsnmp_v3_trap.so",
    "libnetflow_v9_ipfix.so"
]

def main():
    parser = argparse.ArgumentParser(description="Issue an Aryorithm Commercial License (.lic)")
    parser.add_argument("--customer", required=True, help="Customer or organization name")
    parser.add_argument("--tier", choices=["ENTERPRISE_IT", "CRITICAL_OT", "SOVEREIGN_DEFENSE"], default="CRITICAL_OT")
    parser.add_argument("--days", type=int, default=365, help="Validity period in days (0 for perpetual)")
    parser.add_argument("--nodes", type=int, default=10, help="Maximum authorized appliances")
    parser.add_argument("--hw-uuid", default="", help="Hardware UUID or TPM fingerprint to lock license to (optional)")
    parser.add_argument("--output", default="license.lic", help="Output file path")
    args = parser.parse_args()

    priv_path = os.path.join(KEY_DIR, "master_private.key")
    if not os.path.exists(priv_path):
        print("[-] Error: master_private.key not found. Run keygen.py first.")
        sys.exit(1)

    with open(priv_path, "rb") as f:
        priv_bytes = f.read()
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    now_sec = int(time.time())
    expires_sec = (now_sec + (args.days * 86400)) if args.days > 0 else 0

    # Determine entitlements based on tier
    if args.tier in ("CRITICAL_OT", "SOVEREIGN_DEFENSE"):
        modules = ALL_26_MODULES
        plugins = ALL_30_PLUGINS
    else: # ENTERPRISE_IT (Excludes heavy industrial SCADA & medical)
        modules = [m for m in ALL_26_MODULES if m not in ("17_iot_sec", "18_cps_sec", "20_fse", "21_side_channel", "26_ddp")]
        plugins = ["libcef_forwarder.so", "libleef_forwarder.so", "libsyslog_rfc5424.so", "libkafka_producer.so", "libbacnet_building.so"]

    # Canonical payload for signing
    claims = {
        "license_id": f"LIC-{now_sec}-{args.customer[:3].upper()}",
        "customer": args.customer,
        "tier": args.tier,
        "issued_at": now_sec,
        "expires_at": expires_sec,
        "max_nodes": args.nodes,
        "locked_hardware_uuid": args.hw_uuid.strip(),
        "authorized_modules": modules,
        "authorized_plugins": plugins
    }

    # Deterministic canonical JSON bytes
    canonical_bytes = json.dumps(claims, sort_keys=True, separators=(',', ':')).encode('utf-8')

    # Sign with Ed25519 (64-byte raw signature)
    raw_signature = private_key.sign(canonical_bytes)
    b64_signature = base64.b64encode(raw_signature).decode('utf-8')

    envelope = {
        "claims": claims,
        "signature_algorithm": "ED25519",
        "signature": b64_signature
    }

    with open(args.output, "w") as f:
        json.dump(envelope, f, indent=2)

    print("==================================================================")
    print("  COMMERCIAL LICENSE ENVELOPE ISSUED SUCCESSFULLY")
    print("==================================================================")
    print(f"  • License ID    : {claims['license_id']}")
    print(f"  • Customer      : {claims['customer']}")
    print(f"  • Tier          : {claims['tier']}")
    print(f"  • Max Nodes     : {claims['max_nodes']}")
    print(f"  • Valid Days    : {args.days} (Expires: {time.ctime(expires_sec) if expires_sec else 'Perpetual'})")
    print(f"  • Hardware Lock : {'None (Floating)' if not args.hw_uuid else args.hw_uuid}")
    print(f"  • Modules Count : {len(modules)} / 26")
    print(f"  • Plugins Count : {len(plugins)} / 30")
    print(f"  • Output File   : {args.output}")
    print("==================================================================")

if __name__ == "__main__":
    main()