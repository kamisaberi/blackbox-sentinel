#!/usr/bin/env python3
"""
Aryorithm Commercial License Issuer (Self-Contained & Deterministic)
"""

import os
import sys
import json
import time
import base64
import argparse
from cryptography.hazmat.primitives.asymmetric import ed25519

KEY_DIR = os.path.dirname(os.path.abspath(__file__))

# RFC 8032 Vector 1 Master Private Key Seed (Matches C++ ARYORITHM_MASTER_PUBKEY)
DEFAULT_PRIVATE_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

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
    parser.add_argument("--customer", required=True, help="Customer name")
    parser.add_argument("--tier", choices=["ENTERPRISE_IT", "CRITICAL_OT", "SOVEREIGN_DEFENSE"], default="CRITICAL_OT")
    parser.add_argument("--days", type=int, default=365, help="Validity period in days")
    parser.add_argument("--nodes", type=int, default=25, help="Max nodes")
    parser.add_argument("--hw-uuid", default="", help="Hardware UUID or full ARY-HW- token")
    parser.add_argument("--output", default="/etc/sentinel/license.lic", help="Output file path")
    args = parser.parse_args()

    # Automatically strip ARY-HW- prefix if passed
    clean_uuid = args.hw_uuid.replace("ARY-HW-", "").strip()

    # Load private key from file if present, else use default matched seed
    priv_path = os.path.join(KEY_DIR, "master_private.key")
    if os.path.exists(priv_path) and os.path.getsize(priv_path) == 32:
        with open(priv_path, "rb") as f:
            priv_bytes = f.read()
    else:
        priv_bytes = bytes.fromhex(DEFAULT_PRIVATE_SEED_HEX)
        with open(priv_path, "wb") as f:
            f.write(priv_bytes)

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    now_sec = int(time.time())
    expires_sec = (now_sec + (args.days * 86400)) if args.days > 0 else 0

    if args.tier in ("CRITICAL_OT", "SOVEREIGN_DEFENSE"):
        modules = ALL_26_MODULES
        plugins = ALL_30_PLUGINS
    else:
        modules = [m for m in ALL_26_MODULES if m not in ("17_iot_sec", "18_cps_sec", "20_fse", "21_side_channel", "26_ddp")]
        plugins = ["libcef_forwarder.so", "libleef_forwarder.so", "libsyslog_rfc5424.so", "libkafka_producer.so", "libbacnet_building.so"]

    claims = {
        "license_id": f"LIC-{now_sec}-{args.customer[:3].upper()}",
        "customer": args.customer,
        "tier": args.tier,
        "issued_at": now_sec,
        "expires_at": expires_sec,
        "max_nodes": args.nodes,
        "locked_hardware_uuid": clean_uuid,
        "authorized_modules": modules,
        "authorized_plugins": plugins
    }

    # 1. Base64 encode the claims string
    payload_json = json.dumps(claims)
    payload_b64 = base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')

    # 2. Sign the exact payload_b64 string
    raw_signature = private_key.sign(payload_b64.encode('utf-8'))
    signature_b64 = base64.b64encode(raw_signature).decode('utf-8')

    envelope = {
        "payload_b64": payload_b64,
        "signature_b64": signature_b64,
        "signature_algorithm": "ED25519"
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(envelope, f, indent=2)

    print("==================================================================")
    print("  COMMERCIAL LICENSE ENVELOPE ISSUED SUCCESSFULLY")
    print("==================================================================")
    print(f"  • License ID    : {claims['license_id']}")
    print(f"  • Customer      : {claims['customer']}")
    print(f"  • Tier          : {claims['tier']}")
    print(f"  • Hardware Lock : {clean_uuid if clean_uuid else 'Floating'}")
    print(f"  • Modules Count : {len(modules)} / 26")
    print(f"  • Output File   : {args.output}")
    print("==================================================================")

if __name__ == "__main__":
    main()