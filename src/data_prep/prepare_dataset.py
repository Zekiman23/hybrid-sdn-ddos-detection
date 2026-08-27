import pandas as pd
import glob
import numpy as np
import os
from sklearn.utils import shuffle

# --- CONFIGURATION ---
RAW_PATH = "../../data/raw/*.csv"
OUT_PATH = "../../data/processed/features_balanced.csv"
MAX_TOTAL_RECORDS = 800000

# Keyword mapping to handle inconsistent header names across 2017/2019 datasets
KEYWORD_MAPPING = {
    'duration': 'Duration',
    'fwd_packets': 'Total Fwd Packets',
    'bwd_packets': 'Total Backward Packets',
    'bytes_per_sec': 'Flow Bytes/s',
    'packets_per_sec': 'Flow Packets/s',
    'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
    'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
    'syn_count': 'SYN Flag Count',
    'ack_count': 'ACK Flag Count',
    'label': 'Label'
}

def find_best_column(actual_cols, target_keyword):
    """Finds a column name that contains the target keyword, ignoring spaces/case."""
    target_clean = target_keyword.lower().replace(" ", "")
    for col in actual_cols:
        col_clean = col.lower().replace(" ", "").replace("_", "")
        if target_clean in col_clean:
            return col
    return None

def load_and_process():
    files = glob.glob(RAW_PATH)
    if not files:
        raise RuntimeError(f"No CSV files found in {RAW_PATH}.")

    benign_frames = []
    attack_frames = []

    # --- SCHEMA MAPPING TRACKING (for end-of-run summary) ---
    used_files = []
    skipped_files = {}   # file_name -> list of missing nicknames

    for f in files:
        file_name = os.path.basename(f)
        print(f"--- Processing: {file_name} ---")
        try:
            # Read header to map columns dynamically
            df_sample = pd.read_csv(f, nrows=0)
            actual_columns = df_sample.columns.tolist()
            
            this_file_map = {}
            missing = []
            for nickname, keyword in KEYWORD_MAPPING.items():
                real_col = find_best_column(actual_columns, keyword)
                if real_col:
                    this_file_map[real_col] = nickname
                else:
                    missing.append(nickname)
            
            # Check if all 10 required features were found
            if len(this_file_map) < len(KEYWORD_MAPPING):
                found = list(this_file_map.keys())
                print(f"  ⚠️ Skipping: Only found {len(found)}/{len(KEYWORD_MAPPING)} columns. Missing: {missing}")
                skipped_files[file_name] = missing
                continue

            # Load file
            df = pd.read_csv(f, usecols=list(this_file_map.keys()), low_memory=False)
            df = df.rename(columns=this_file_map)
            df = df.replace([np.inf, -np.inf], np.nan).dropna()
            
            # Binary Labeling
            df['label'] = df['label'].apply(lambda x: 0 if 'BENIGN' in str(x).upper() else 1)
            
            # Add Source Tracking
            df['source_file'] = file_name

            # --- REMOVE DUPLICATE ROWS (within this file) ---
            # CICIDS-style captures commonly contain exact-duplicate flow rows.
            # Dropping them here, before any train/test split happens downstream,
            # prevents identical rows from ending up on both sides of a later split.
            before = len(df)
            df = df.drop_duplicates(subset=[c for c in df.columns if c != 'source_file'])
            removed = before - len(df)
            if removed:
                print(f"  🧹 Dropped {removed} duplicate rows ({removed / before:.1%})")

            used_files.append(file_name)

            b_rows = df[df['label'] == 0]
            a_rows = df[df['label'] == 1]
            
            if not b_rows.empty: benign_frames.append(b_rows)
            if not a_rows.empty: attack_frames.append(a_rows)
            
            print(f"  ✅ Extracted {len(b_rows)} Benign, {len(a_rows)} Attack rows.")

        except Exception as e:
            print(f"  ❌ Error processing {f}: {e}")
            skipped_files[file_name] = [f"ERROR: {e}"]

    # --- SCHEMA MAPPING SUMMARY ---
    print("\n=== SCHEMA MAPPING SUMMARY ===")
    print(f"Files processed: {len(files)} | Files used: {len(used_files)} | Files skipped: {len(skipped_files)}")

    if skipped_files:
        print("Skipped files and missing columns:")
        for fname, missing_cols in skipped_files.items():
            print(f"  - {fname}: missing {missing_cols}")

        # Tally which target columns are most frequently the cause of a skip
        missing_tally = {}
        for missing_cols in skipped_files.values():
            for col in missing_cols:
                missing_tally[col] = missing_tally.get(col, 0) + 1
        top_col, top_count = max(missing_tally.items(), key=lambda x: x[1])
        print(f"Most frequently missing target column: {top_col} ({top_count} files)")
    print("=" * 30)

    if not benign_frames or not attack_frames:
        raise ValueError("Could not find enough valid data to balance.")

    # Merge buckets
    all_benign = pd.concat(benign_frames, ignore_index=True)
    all_attack_raw = pd.concat(attack_frames, ignore_index=True)

    # --- REMOVE DUPLICATE ROWS (across files) ---
    # Some CICIDS distributions repeat the same traffic across multiple daily
    # capture files. Cross-file duplicates are just as capable of causing
    # train/test leakage as within-file duplicates, so drop them too.
    feature_cols = [c for c in all_benign.columns if c != 'source_file']

    before_b = len(all_benign)
    all_benign = all_benign.drop_duplicates(subset=feature_cols)
    print(f"\nCross-file benign dedup: {before_b} -> {len(all_benign)}")

    before_a = len(all_attack_raw)
    all_attack_raw = all_attack_raw.drop_duplicates(subset=feature_cols)
    print(f"Cross-file attack dedup: {before_a} -> {len(all_attack_raw)}")

    # --- EQUAL REPRESENTATION LOGIC (with shortfall redistribution) ---
    target_total_attack = MAX_TOTAL_RECORDS // 2
    unique_attack_files = list(all_attack_raw['source_file'].unique())

    print(f"\nBalancing Attack types: {len(unique_attack_files)} files detected.")

    # A flat equal-share-per-file target wastes capacity: files with fewer
    # rows than their share leave quota unused, while files with plenty of
    # surplus get capped at the same share even though they could give more.
    # This loop repeatedly reallocates any unused quota from exhausted files
    # to files that still have surplus, instead of silently undershooting
    # target_total_attack (see project discussion for a worked example: a
    # handful of low-volume attack files were leaving ~120k rows of quota
    # unclaimed while several other files had hundreds of thousands of
    # unused surplus rows).
    remaining_files = list(unique_attack_files)
    remaining_target = target_total_attack
    taken_so_far = {f: 0 for f in unique_attack_files}
    balanced_attack_list = []

    while remaining_files and remaining_target > 0:
        share = remaining_target // len(remaining_files)
        if share <= 0:
            # Not enough remaining target to give every remaining file at
            # least 1 more row - stop rather than looping forever.
            break

        next_round_files = []
        for attack_file in remaining_files:
            subset = all_attack_raw[all_attack_raw['source_file'] == attack_file]
            available = len(subset) - taken_so_far[attack_file]
            if available <= 0:
                continue

            n_to_take = min(available, share)
            already_taken_idx = subset.index[:taken_so_far[attack_file]]
            pool = subset.drop(already_taken_idx)
            taken_subset = pool.sample(n=n_to_take, random_state=42)

            balanced_attack_list.append(taken_subset)
            taken_so_far[attack_file] += n_to_take
            remaining_target -= n_to_take

            if available - n_to_take > 0:
                # This file still has surplus left for another round.
                next_round_files.append(attack_file)

        if next_round_files == remaining_files:
            # No file could be fully exhausted this round (all still have
            # leftover surplus) - avoid an infinite loop by stopping once
            # remaining_target has been distributed as evenly as possible.
            if remaining_target <= 0:
                break
            # Re-run with the same file set but smaller share next loop;
            # guard against zero-progress by breaking if share can't shrink.
            if share == 0:
                break
        remaining_files = next_round_files

    balanced_attack = pd.concat(balanced_attack_list, ignore_index=True)
    final_attack_count = len(balanced_attack)
    print(f"Final attack count: {final_attack_count} (target was {target_total_attack})")
    if final_attack_count < target_total_attack:
        print(f"  ⚠️ Could not reach target - total available unique attack rows "
              f"across all files ({len(all_attack_raw)}) is less than target_total_attack.")

    # Balance Benign to match the final Attack count
    n_benign = min(final_attack_count, len(all_benign))
    if n_benign < final_attack_count:
        print(f"  ⚠️ Not enough benign rows ({len(all_benign)}) to match attack count "
              f"({final_attack_count}); using {n_benign} instead.")

    balanced_benign = all_benign.sample(n=n_benign, random_state=42)

    # Final Combine
    final_df = pd.concat([balanced_benign, balanced_attack], ignore_index=True)

    # --- PRINT COMPOSITION TABLE ---
    print("\n" + "="*50)
    print("FINAL DATASET COMPOSITION BY SOURCE FILE")
    print("="*50)
    summary = final_df.groupby(['source_file', 'label']).size().unstack(fill_value=0)
    summary.columns = ['Benign (0)', 'Attack (1)']
    print(summary)
    print("="*50)

    # source_file is dropped here (v1: no grouping key retained). Use v2
    # of this script instead if you want a training script to be able to
    # do a group-aware split by capture file.
    return shuffle(final_df.drop(columns=['source_file']), random_state=42).reset_index(drop=True)

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    
    print("Starting Feature Preparation Assembly Line...")
    processed_df = load_and_process()
    
    # Save the unscaled, balanced data
    processed_df.to_csv(OUT_PATH, index=False)
    
    print(f"\nSUCCESS! Total Records: {len(processed_df)}")
    print(f"Saved to: {OUT_PATH}")
