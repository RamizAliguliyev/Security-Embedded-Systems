import hmac
import hashlib
import time
import statistics
from dataclasses import dataclass


SECRET_KEY = b"shared_secret_key_for_sensor_and_twin"
FRESHNESS_WINDOW = 2.0  # seconds


@dataclass
class Packet:
    seq: int
    timestamp: float
    payload: float
    mac: str = ""


def create_hmac(seq, timestamp, payload):
    message = f"{seq}|{timestamp}|{payload}".encode()
    return hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()


def create_packet(seq, payload):
    timestamp = time.time()
    mac = create_hmac(seq, timestamp, payload)
    return Packet(seq, timestamp, payload, mac)


class DigitalTwinVerifier:
    def __init__(self):
        self.last_seq = -1
        self.accepted_packets = 0
        self.rejected_packets = 0
        self.verify_latencies = []

    def verify_packet(self, packet):
        start = time.perf_counter()

        expected_mac = create_hmac(packet.seq, packet.timestamp, packet.payload)

        mac_valid = hmac.compare_digest(packet.mac, expected_mac)
        seq_valid = packet.seq > self.last_seq
        time_valid = abs(time.time() - packet.timestamp) <= FRESHNESS_WINDOW

        accepted = mac_valid and seq_valid and time_valid

        if accepted:
            self.last_seq = packet.seq
            self.accepted_packets += 1
        else:
            self.rejected_packets += 1

        end = time.perf_counter()
        self.verify_latencies.append((end - start) * 1_000_000)  # microseconds

        return accepted


def generate_plant_telemetry(total_packets=100, fault_start=60):
    """
    Before fault: temperature is normal.
    After fault: temperature rises dangerously.
    """
    packets = []

    for seq in range(total_packets):
        if seq < fault_start:
            temperature = 25.0 + (seq % 5) * 0.2
        else:
            temperature = 35.0 + (seq - fault_start) * 0.8

        packets.append(create_packet(seq, round(temperature, 2)))
        time.sleep(0.005)

    return packets


def scenario_1_normal_no_attack(packets):
    twin_values = []

    for packet in packets:
        twin_values.append(packet.payload)

    return {
        "scenario": "S1 Normal traffic",
        "accepted": len(packets),
        "rejected": 0,
        "replay_accepted_rate": "N/A",
        "false_reject_rate": "0%",
        "avg_latency_us": "N/A",
        "twin_values": twin_values
    }


def scenario_2_replay_no_defence(packets, fault_start=60):
    """
    Attacker replays old healthy packets during the fault.
    There is no verifier, so the twin accepts everything.
    """
    captured_healthy_packets = packets[20:30]
    twin_values = []
    replayed_count = 0

    for i, packet in enumerate(packets):
        if i < fault_start:
            twin_values.append(packet.payload)
        else:
            replayed_packet = captured_healthy_packets[i % len(captured_healthy_packets)]
            twin_values.append(replayed_packet.payload)
            replayed_count += 1

    return {
        "scenario": "S2 Replay attack, no defence",
        "accepted": len(packets),
        "rejected": 0,
        "replay_accepted_rate": "100%",
        "false_reject_rate": "N/A",
        "avg_latency_us": "N/A",
        "twin_values": twin_values
    }


def scenario_3_replay_with_hmac_defence(packets, fault_start=60):
    """
    Attacker replays old authenticated packets.
    HMAC is still valid, but sequence number and timestamp checks reject them.
    """
    verifier = DigitalTwinVerifier()
    captured_healthy_packets = packets[20:30]

    twin_values = []
    replay_attempts = 0
    replay_accepted = 0
    legitimate_rejected = 0

    for i, packet in enumerate(packets):
        if i < fault_start:
            accepted = verifier.verify_packet(packet)

            if accepted:
                twin_values.append(packet.payload)
            else:
                legitimate_rejected += 1
                twin_values.append(None)

        else:
            replayed_packet = captured_healthy_packets[i % len(captured_healthy_packets)]
            replay_attempts += 1

            accepted = verifier.verify_packet(replayed_packet)

            if accepted:
                replay_accepted += 1
                twin_values.append(replayed_packet.payload)
            else:
                twin_values.append(None)

    replay_acceptance_rate = (replay_accepted / replay_attempts) * 100
    false_reject_rate = (legitimate_rejected / fault_start) * 100

    avg_latency = statistics.mean(verifier.verify_latencies)

    return {
        "scenario": "S3 Replay attack with HMAC defence",
        "accepted": verifier.accepted_packets,
        "rejected": verifier.rejected_packets,
        "replay_accepted_rate": f"{replay_acceptance_rate:.1f}%",
        "false_reject_rate": f"{false_reject_rate:.1f}%",
        "avg_latency_us": f"{avg_latency:.2f}",
        "twin_values": twin_values
    }


def print_results(results):
    print("\nDigital Twin Replay Attack Simulation Results")
    print("-" * 80)
    print(f"{'Scenario':35} | {'Accepted':8} | {'Rejected':8} | {'Replay accepted':15} | {'False rejects':13} | {'Avg latency'}")
    print("-" * 80)

    for result in results:
        print(
            f"{result['scenario']:35} | "
            f"{result['accepted']:<8} | "
            f"{result['rejected']:<8} | "
            f"{result['replay_accepted_rate']:<15} | "
            f"{result['false_reject_rate']:<13} | "
            f"{result['avg_latency_us']}"
        )


def main():
    packets = generate_plant_telemetry(total_packets=100, fault_start=60)

    s1 = scenario_1_normal_no_attack(packets)
    s2 = scenario_2_replay_no_defence(packets)
    s3 = scenario_3_replay_with_hmac_defence(packets)

    results = [s1, s2, s3]
    print_results(results)

    print("\nPoster interpretation:")
    print("S2 shows that without message-level freshness checks, replayed healthy telemetry is accepted.")
    print("S3 shows that HMAC alone is not enough; sequence numbers and timestamps reject old but authentic packets.")
    print("This demonstrates integrity, authenticity, and freshness for Digital Twin synchronisation.")


if __name__ == "__main__":
    main()