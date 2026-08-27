import pandas as pd
import os

LOG_FILE = "../../logs/online_test_results/latency_log.csv"

def run_analysis():
    if not os.path.exists(LOG_FILE):
        print(f"Error: {LOG_FILE} not found!")
        return

    # 1. THE ALIGNMENT FIX:
    # We define 13 columns to match your actual data row [...,22.8, 50, 50]
    # This ensures 'is_correct' (Index 7) and 'decision' (Index 5) are mapped correctly.
    col_names = [
        'timestamp',            # 0
        'src_mac',              # 1
        'dst_mac',              # 2
        'total_latency_ms',     # 3
        'inference_latency_ms', # 4
        'decision',             # 5
        'ml_call_percentage',   # 6
        'is_correct',           # 7
        'time_to_mitigation_s', # 8
        'cpu_utilization_pct',  # 9
        'mem_utilization_pct',  # 10
        'extra_metric_1',       # 11 (The first '50')
        'extra_metric_2'        # 12 (The second '50')
    ]

    # 2. Load and ignore the conflicting header rows (skiprows=2)
    try:
        df = pd.read_csv(
            LOG_FILE, 
            names=col_names, 
            header=None, 
            skiprows=2, 
            on_bad_lines='skip'
        )
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return
    
    if df.empty:
        print("Log file is empty.")
        return

    # 3. Data Cleaning: Force correct types
    # Strip whitespace from 'is_correct' string before mapping
    df['is_correct'] = df['is_correct'].astype(str).str.strip().map({'True': True, 'False': False})
    
    numeric_cols = [
        'total_latency_ms', 'inference_latency_ms', 'decision', 
        'time_to_mitigation_s', 'cpu_utilization_pct', 
        'mem_utilization_pct', 'ml_call_percentage'
    ]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # 4. Confusion Matrix Logic
    tp = len(df[(df['is_correct'] == True) & (df['decision'] == 1)])
    tn = len(df[(df['is_correct'] == True) & (df['decision'] == 0)])
    fp = len(df[(df['is_correct'] == False) & (df['decision'] == 1)])
    fn = len(df[(df['is_correct'] == False) & (df['decision'] == 0)])

    # 5. Performance Metrics
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    # 6. Latency & Mitigation
    ttm_df = df[df['time_to_mitigation_s'] > 0]
    avg_ttm = ttm_df['time_to_mitigation_s'].mean() if not ttm_df.empty else 0
    
    avg_latency = df['total_latency_ms'].mean()
    avg_inf_latency = df['inference_latency_ms'].mean()
    
    # 7. Resource Utilization
    avg_cpu = df['cpu_utilization_pct'].mean()
    avg_mem = df['mem_utilization_pct'].mean()
    avg_ml_calls = df['ml_call_percentage'].mean()

    # Logic for Mitigation Success
    mitigation_attempts = len(df[df['decision'] == 1])
    mitigation_successes = len(ttm_df[ttm_df['decision'] == 1])
    mitigation_success_rate = (mitigation_successes / mitigation_attempts * 100) if mitigation_attempts > 0 else 0

    # --- Print Final Thesis Report ---
    print("\n" + "="*50)
    print("      HYBRID SDN DDoS CONTROLLER: FINAL REPORT")
    print("="*50)
    print(f"Total Evaluated Events:          {total}")
    print("-" * 50)
    print(f"Detection Rate (Recall):         {detection_rate*100:.2f}%")
    print(f"False Positive Rate (FPR):       {fpr*100:.2f}%")
    print(f"System Accuracy:                 {accuracy*100:.2f}%")
    print("-" * 50)
    print(f"Avg. Mitigation Latency (TTM):   {avg_ttm:.4f} seconds")
    print(f"Avg. Total Processing Latency:   {avg_latency:.2f} ms")
    print(f"Avg. ML Inference Latency:       {avg_inf_latency:.2f} ms")
    print("-" * 50)
    print(f"Avg. CPU Utilization:            {avg_cpu:.1f}%")
    print(f"Avg. Memory Utilization:         {avg_mem:.1f}%")
    print(f"Avg. ML Overhead (per Flow):     {avg_ml_calls:.2f}%")
    print(f"Mitigation Success Rate:         {mitigation_success_rate:.2f}%")
    print("="*50 + "\n")

if __name__ == "__main__":
    run_analysis()