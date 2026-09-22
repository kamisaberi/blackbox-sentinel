#!/usr/bin/env python3
"""
Blackbox Sentinel: Edge Event & Collective Defense Trigger
Sends simulated events directly through Nexus to test:
1. Threat Broadcast ("Attacked Once, Immune Everywhere")
2. Candidate Vector Streaming to xinfer-forge
"""

import os
import sys
import time
import random
import grpc

# Add generated protobuf path
GEN_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../proto_gen"))
if not os.path.exists(GEN_DIR):
    GEN_DIR = "/home/kami/sentinel-nexus/tools/mock_appliance/generated"
sys.path.append(GEN_DIR)

import telemetry_pb2
import telemetry_pb2_grpc
import intelligence_pb2
import intelligence_pb2_grpc

NEXUS_ENDPOINT = "localhost:50051"

def test_threat_broadcast(attacker_ip="198.51.100.99"):
    print(f"\n[*] 1. Simulating local exploit detection on attacker IP: {attacker_ip}...")
    channel = grpc.insecure_channel(NEXUS_ENDPOINT)
    intel_stub = intelligence_pb2_grpc.IntelligenceServiceStub(channel)

    def threat_stream():
        yield intelligence_pb2.ThreatIndicator(
            origin_node_id="SIMULATED-EDGE-PROBE",
            attacker_ip=attacker_ip,
            port=445,
            type=intelligence_pb2.THREAT_EXPLOIT_PAYLOAD,
            confidence=0.99,
            timestamp_ns=time.time_ns()
        )
        time.sleep(1)

    print("[*] Dispatching ThreatIndicator to Sentinel Nexus...")
    rule_stream = intel_stub.SyncCollectiveImmunity(threat_stream())
    for rule in rule_stream:
        print(f"[+] Broadcast acknowledged by Nexus -> Rule: {rule.rule_id} for IP: {rule.target_ip}")
        break

def test_stream_uncertain_vectors(node_id="BLACKBOX-EDGE-01", count=25):
    print(f"\n[*] 2. Streaming {count} high-uncertainty NetFlow vectors for xinfer-forge active learning...")
    channel = grpc.insecure_channel(NEXUS_ENDPOINT)
    telemetry_stub = telemetry_pb2_grpc.TelemetryServiceStub(channel)

    def vector_gen():
        vectors = []
        for i in range(count):
            vectors.append(telemetry_pb2.CandidateVector(
                event_id=random.randint(10000, 99999),
                timestamp_ns=time.time_ns(),
                features=[random.uniform(-1.0, 1.0) for _ in range(32)],
                inference_uncertainty=random.uniform(0.42, 0.58), # Active learning range [0.40 - 0.60]
                autoencoder_recon_loss=random.uniform(0.76, 0.95), # High outlier novelty loss
                triggered_kernel_drop=True
            ))
        yield telemetry_pb2.FeatureVectorStream(node_id=node_id, vectors=vectors)

    summary = telemetry_stub.StreamCandidateVectors(vector_gen())
    print(f"[+] Telemetry Ingest Complete!")
    print(f"    Total Received: {summary.total_received}")
    print(f"    Routed to xinfer-forge: {summary.routed_to_forge}")

if __name__ == "__main__":
    test_threat_broadcast("198.51.100.99")
    test_stream_uncertain_vectors("BLACKBOX-EDGE-01", 30)