# Replay-Resistant Telemetry for Digital Twin Synchronisation

A Python prototype showing how **replay attacks** can desynchronise a Digital Twin from the physical system it mirrors, and how an **HMAC + sequence number + timestamp** envelope stops them.

This repository accompanies the research poster *"Replay Resistant Telemetry for Digital Twin Synchronisation"* and the group paper *"SoK: A Systematisation of Attacks on Digital Twin Architectures in Embedded and Control Systems"* (University of Sheffield).

---

## Problem

Digital Twins depend on a continuous stream of telemetry from sensors and PLCs, often carried over industrial protocols (MQTT, OPC-UA, Modbus/TCP) that do not guarantee message freshness.

An on-path attacker can capture legitimate "healthy" telemetry and **replay it during a real fault**. The twin keeps showing a normal state while the plant is failing. This is the same pattern used by Stuxnet against SCADA monitoring, and in a Digital Twin the false state spreads further: into dashboards, anomaly detection and predictive maintenance.

## Proposed Defence

Each telemetry sample is wrapped in an authenticated envelope at the sender:

```
packet = (seq, ts, payload, HMAC(K, seq || ts || payload))
```

| Field     | Purpose |
|-----------|---------|
| `seq`     | Monotonically increasing sequence number, so old packets are rejected |
| `ts`      | Creation timestamp, so packets outside the freshness window are rejected |
| `payload` | Sensor value (e.g. temperature) |
| `HMAC`    | HMAC-SHA256 with shared key `K`, proving origin and integrity |

The **verifier** sits at the Digital Twin input boundary and accepts a packet only if all three checks pass:

1. HMAC is valid
2. `seq > last_seq`
3. `|now − ts| ≤ freshness window` (2 s in the prototype)

HMAC alone is not enough. A replayed packet is authentic, so its HMAC is still valid. The sequence and timestamp checks are what give replay protection.

```
Sensor / PLC → Envelope Module → Network (attacker) → Verifier → Twin Engine
                (HMAC, seq, ts)                          ↓
                                                     Reject Log
```

## Experiment

`Experiment.py` simulates a sensor-to-twin telemetry stream:

- **100 packets** in total
- **Packets 0–59:** normal operation, temperature around 25 °C
- **Packets 60–99:** simulated fault, temperature rising progressively from 35 °C
- **Attack:** 10 healthy packets (20–29) are captured and replayed in a loop across the 40-packet fault window (40 replay attempts)

Three scenarios are compared:

| Scenario | Description |
|----------|-------------|
| **S1** Normal traffic | No attack, no defence (baseline) |
| **S2** Replay, no defence | Twin accepts every replayed packet |
| **S3** Replay, HMAC defence | Verifier checks HMAC, sequence and freshness |

### Results

| Scenario | Accepted | Rejected | Replay acceptance | False rejects | Avg latency |
|----------|---------:|---------:|------------------:|--------------:|------------:|
| S1 Normal traffic | 100 | 0 | N/A | 0% | N/A |
| S2 Replay, no defence | 100 | 0 | 100% | N/A | N/A |
| S3 HMAC defence | 60 | 40 | **0.0%** | **0.0%** | ~2.56 µs |

All 40 replayed packets are rejected and no legitimate packets are lost. The sequence-number check fails first for every replay, so the defence still works even when the attacker replays packets captured very recently (inside the freshness window).

Latency values depend on your machine and will vary between runs.

## How to Run

Requires **Python 3.7+**. Only the standard library is used, so there is nothing to install.

```bash
git clone https://github.com/RamizAliguliyev/<repo-name>.git
cd <repo-name>
python Experiment.py
```

The script prints a results table and a short interpretation of each scenario.

## Repository Contents

| File | Description |
|------|-------------|
| `Experiment.py` | Python simulation of the replay attack and HMAC-based defence |
| `<poster>.pdf` | Research poster: *Replay Resistant Telemetry for Digital Twin Synchronisation* |
| `<sok-paper>.pdf` | Group SoK paper on attacks against Digital Twin architectures |
| `README.md` | This file |

## Trust Assumptions

- The shared key `K` is securely provisioned before deployment.
- Sender and verifier clocks are loosely synchronised (small drift is tolerated by the window).
- The verifier itself is not compromised.
- Per-sender `last_seq` is persisted across restarts, which prevents reset-replay.
- Physical sensor compromise and key theft are **out of scope**.

## Limitations and Trade-offs

- **Overhead:** about 48 extra bytes per packet plus microsecond-level verification. This is negligible at normal sensor rates but matters at kHz update rates or on legacy PLCs.
- **Key management:** `K` must be provisioned and rotated across all senders.
- **Clock tension:** a tighter freshness window catches more replays but raises false rejects under clock drift.
- **Deployment:** both sender and verifier must be modified, which is harder for brownfield systems with legacy PLCs.
- **Threats to validity:** single-host simulation, simplified attacker model and synthetic telemetry. Real networks add jitter, packet loss and clock drift.

> **Note:** The secret key is hard-coded in `Experiment.py` for demonstration only. In a real deployment keys must never be stored in source code.

## References

- P. Syverson, "A Taxonomy of Replay Attacks," *IEEE Computer Security Foundations Workshop*, 1994.
- Y. Mo and B. Sinopoli, "Secure Control Against Replay Attacks," *47th Allerton Conference*, 2009.
- M. Pooyandeh and I. Sohn, "A Time-Stamp Attack on Digital Twin-Based Lithium-Ion Battery Monitoring for Electric Vehicles," *ICAIIC*, 2024.
- S. Karnouskos, "Stuxnet Worm Impact on Industrial Cyber-Physical System Security," *IECON*, 2011.
- E. Karaarslan and M. Babiker, "Digital Twin Security Threats and Countermeasures: An Introduction," *ISCTURKEY*, 2021.

## Authors

**Poster and prototype:** Ramiz Aliguliyev, University of Sheffield

**SoK paper:** Rahim Abdullazade, Ramiz Aliguliyev, Sujeet Gowdham Iyappan, Praveen Kunja Mahaprabu, Department of Computer Science, University of Sheffield
