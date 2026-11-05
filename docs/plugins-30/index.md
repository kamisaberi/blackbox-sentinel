# 30 Protocol Dissector Plugins

`blackbox-sentinel` includes 30 industrial, transport, medical, and energy protocol dissector shared objects (`libsentinel_plugin_*.so`).

## Section Navigation

- [Plugin Architecture](./plugin-architecture.md): Zero-allocation C++20 ABI contract and `DissectionResult` structures.

### Industrial OT
- [Modbus TCP](./industrial-ot/modbus-tcp.md): Inspects Modbus TCP port 502 for illegal register mutations.
- [DNP3 Substation](./industrial-ot/dnp3-substation.md): Electric utility telecontrol inspector for port 20000.
- [Siemens S7Comm](./industrial-ot/siemens-s7comm.md): S7-300/1200/1500 PLC dissector for port 102.
- [PROFINET RT](./industrial-ot/profinet-rt.md): High-speed industrial Ethernet frame dissector (EtherType 0x8892).
- [EtherNet/IP CIP](./industrial-ot/ethernet-ip-cip.md): CIP Motion & Safety dissector for port 44818.
- [HART-IP](./industrial-ot/hart-ip.md): Process automation wireless sensor dissector for port 5094.
- [Mitsubishi MELSEC](./industrial-ot/mitsubishi-melsec.md): MC Protocol dissector for Mitsubishi iQ-R/FX PLCs.
- [Omron FINS](./industrial-ot/omron-fins.md): Omron factory controller dissector for port 9600.

### Energy & Utilities
- [IEC 60870-5-104](./energy-utilities/iec-60870-5-104.md): High-voltage telecontrol dissector for port 2404.
- [IEC 61850 GOOSE](./energy-utilities/iec-61850-goose.md): Substation Layer 2 protection relay multicast dissector (0x88B8).
- [IEC 61850 MMS](./energy-utilities/iec-61850-mms.md): SCADA/HMI client-server dissector for port 102.
- [OPC UA Binary](./energy-utilities/opc-ua-binary.md): Machine-to-machine binary protocol dissector for port 4840.
- [BACnet/IP](./energy-utilities/bacnet-ip.md): Smart building automation dissector for port 47808 (`0xBAC0`).
- [Modbus RTU Serial](./energy-utilities/modbus-rtu-serial.md): Serial-over-IP dissector with AVX2 CRC-16 validation.
- [FOUNDATION Fieldbus](./energy-utilities/foundation-fieldbus.md): Process refinery HSE/H1 block dissector.

### Aviation, Maritime & Defense
- [CCSDS Space Guard](./aviation-maritime-defense/ccsds-space-guard.md): Native C++20 space packet dissector for CCSDS 133.0-B-2.
- [MAVLink UAV](./aviation-maritime-defense/mavlink-uav.md): Micro air vehicle telemetry dissector for ports 14550/14551.
- [AIS Maritime](./aviation-maritime-defense/ais-maritime.md): Vessel tracking & ghost-ship injection dissector.
- [NMEA GPS](./aviation-maritime-defense/nmea-gps.md): GNSS sentence dissector with AVX2 checksumming.
- [ADS-B Avionics](./aviation-maritime-defense/ads-b-avionics.md): Mode S & ASTERIX Cat 021 transponder dissector.
- [STANAG 4586](./aviation-maritime-defense/stanag-4586.md): NATO military UAV datalink dissector for port 51000.
- [MIL-STD-1553](./aviation-maritime-defense/mil-std-1553.md): Military avionics bus dissector for port 5553.
- [CAN Bus Automotive](./aviation-maritime-defense/canbus-automotive.md): SocketCAN & CAN-FD automotive frame dissector.

### Healthcare & SIEM Forwarders
- [DICOM PACS](./healthcare-and-siem/dicom-pacs.md): Medical imaging DULP dissector for ports 104 & 11112.
- [HL7 v2](./healthcare-and-siem/hl7-v2.md): EHR clinical messaging dissector over MLLP port 2575.
- [CEF Forwarder](./healthcare-and-siem/cef-forwarder.md): ArcSight Common Event Format SIEM exporter.
- [LEEF Forwarder](./healthcare-and-siem/leef-forwarder.md): IBM QRadar LEEF 2.0 event exporter.
- [Syslog RFC 5424](./healthcare-and-siem/syslog-rfc5424.md): Structured TLS syslog forwarder.
- [Kafka Producer](./healthcare-and-siem/kafka-producer.md): High-throughput Apache Kafka streaming exporter ($> 1\text{M EPS}$).
- [SNMPv3 Trap](./healthcare-and-siem/snmp-v3-trap.md): Encrypted OT Network Management System trap forwarder.
- [NetFlow v9 / IPFIX](./healthcare-and-siem/netflow-v9-ipfix.md): Flow aggregation & exporter for port 2055.
