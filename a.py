
import json
import random
import os
import time
import argparse

# Import your existing EDR event generator
# Keep this script in the same directory as your uploaded generator.
import edr_generator as edr


def generate_logs(output_file, target_gb=1, alert_ratio=0.20):
    target_bytes = int(target_gb * 1_000_000_000)

    events = 0
    alerts = 0
    written = 0

    start = time.time()

    random.seed(42)

    print(f"Generating {target_gb} GB of synthetic EDR logs...")

    with open(output_file, "w", encoding="utf-8", buffering=1024 * 1024) as f:

        while written < target_bytes:

            # Generate benign or simulated alert event
            if random.random() < alert_ratio:
                event = edr.gen_alert()
                alerts += 1
            else:
                event = edr.gen_benign()

            # Convert event to JSONL
            line = json.dumps(
                event,
                separators=(",", ":")
            ) + "\n"

            f.write(line)

            written += len(line.encode("utf-8"))
            events += 1

            # Progress display
            if events % 10000 == 0:
                percentage = min(100, written / target_bytes * 100)

                print(
                    f"\rProgress: {percentage:.2f}% | "
                    f"Events: {events:,} | "
                    f"Size: {written / 1e9:.3f} GB",
                    end="",
                    flush=True
                )

        f.flush()
        os.fsync(f.fileno())

    elapsed = time.time() - start

    print("\n\nGeneration completed!")
    print(f"Output: {output_file}")
    print(f"Size: {os.path.getsize(output_file):,} bytes")
    print(f"Events: {events:,}")
    print(f"Alerts: {alerts:,}")
    print(f"Alert ratio: {alerts/events*100:.2f}%")
    print(f"Time: {elapsed:.2f} seconds")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--size", type=float, default=1)
    parser.add_argument("--alerts", type=float, default=0.20)
    parser.add_argument("--output", default="security_logs.jsonl")

    args = parser.parse_args()

    generate_logs(
        args.output,
        args.size,
        args.alerts
    )
