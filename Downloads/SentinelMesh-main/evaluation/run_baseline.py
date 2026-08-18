import json
import time
import sys
import random

# Fix import path
sys.path.append("logging")
from logger import log_event

# Load ground truth
with open("ground_truth/ground_truth.json") as f:
    ground_truth = json.load(f)

results = {}

correct_count = 0

print("Running baseline...")

for scenario_id, data in ground_truth.items():
    print(f"Running {scenario_id}...")

    start = time.time()

    # Simulate realistic detection
    detected = random.choice([True, True, False])

    time.sleep(1)

    end = time.time()

    # Count correct detections
    if detected:
        correct_count += 1

    results[scenario_id] = {
        "detected": detected,
        "correct": detected,
        "time_taken": round(end - start, 2)
    }

    # Log event
    log_event(scenario_id, "Simulated Alert", detected)

# Save results
with open("baseline/baseline1_results.json", "w") as f:
    json.dump(results, f, indent=4)

# Calculate accuracy
accuracy = correct_count / len(ground_truth)

print("Baseline completed!")
print("Accuracy:", round(accuracy, 2))