from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor

# ================= LOAD MODEL IF AVAILABLE =================
MODEL_PATH = "../../model/rf_model.joblib"
model_bundle = None
model = None
feature_order = None

if os.path.exists(MODEL_PATH):
    model_bundle = joblib.load(MODEL_PATH)
    model = model_bundle["model"]
    feature_order = model_bundle["features"]
    print(f"✔ Model loaded: {MODEL_PATH}")
else:
    print("⚠ No model found — Running in RULE-ONLY mode")

# ================= RULE-BASED CHECK =================
def rule_check(flow):
    score = 0
    if flow.get("packets_per_sec", 0) > 300:
        score += 1
        
    # 2. High Byte Rate (Bandwidth Saturation Check)
    if flow.get("bytes_per_sec", 0) > 500000:
        score += 1
        
    # 3. Massive SYN Burst (Connection Request Flood Check)
    if flow.get("syn_count", 0) > 150:
        score += 1 
        
    # 4. TCP Protocol Asymmetry (SYN Flood / Half-Open Connection Check)
    # Replaces 'ack_count < 10' to avoid misclassifying short benign flows
    syn = flow.get("syn_count", 0)
    ack = flow.get("ack_count", 0)
    
    if syn > 100 and (syn / (ack + 1)) > 10:
        score += 1
        
    return min(score / 4.0, 1.0)

# ===================== FASTAPI APP =====================
app = FastAPI(title="Hybrid DDoS Detection Service", version="1.0")

class FlowData(BaseModel):
    features: dict

@app.post("/detect")
def detect(flow: FlowData):
    # Step 1: Always run fast rule engine first
    rule_score = rule_check(flow.features)
    
    # Step 2: Extreme cases — skip ML completely
    if rule_score == 0.0:
        return {
            "decision": 0,
            "confidence": round(float(rule_score), 4),
            "rule_score": round(float(rule_score), 4),
            "ml_prob": 0.0,
            "mode": "RULE-BENIGN-SKIP",
            "ml_used": False
        }

    if rule_score == 1.0:
        return {
            "decision": 1,
            "confidence": round(float(rule_score), 4),
            "rule_score": round(float(rule_score), 4),
            "ml_prob": 0.0,
            "mode": "RULE-ATTACK-SKIP",
            "ml_used": False
        }

    # Step 3: Uncertain case (0 < rule_score < 1) → run ML and fuse
    if not model_bundle:
        # Fallback when model is missing
        decision = 1 if rule_score >= 0.4 else 0
        return {
            "decision": decision,
            "confidence": round(float(rule_score), 4),
            "rule_score": round(float(rule_score), 4),
            "ml_prob": 0.0,
            "mode": "RULE-ONLY",
            "ml_used": False
        }

    # ML feature alignment check
    missing = [f for f in feature_order if f not in flow.features]
    if missing:
        return {"error": f"Missing features: {missing}"}

    # Prepare raw features and predict without scaling
    x_df = pd.DataFrame([[flow.features[f] for f in feature_order]], columns=feature_order)
    ml_prob = model.predict_proba(x_df)[0][1]
    ml_pred = int(model.predict(x_df)[0])

    # Fusion
    final_score = (ml_prob * 0.7) + (rule_score * 0.3)
    final_label = 1 if final_score > 0.3 else 0

    return {
        "decision": final_label,
        "confidence": round(float(final_score), 4),
        "ml_prob": round(float(ml_prob), 4),
        "rule_score": round(float(rule_score), 4),
        "mode": "HYBRID-FUSION",
        "ml_used": True
    }