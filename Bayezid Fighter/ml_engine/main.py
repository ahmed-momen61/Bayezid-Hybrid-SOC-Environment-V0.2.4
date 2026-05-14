from fastapi import FastAPI, Request
import uvicorn
import numpy as np
from sklearn.ensemble import IsolationForest
import math
import joblib
import os

app = FastAPI(title="Bayezid ML Sniper - Persistent Isolation Forest")

MODEL_FILE = 'bayezid_model.pkl'
DATA_FILE = 'normal_traffic.npy'

print("\n[🧠] Initializing Neural ML Engine (Isolation Forest)...")

if os.path.exists(MODEL_FILE) and os.path.exists(DATA_FILE):
    normal_traffic = np.load(DATA_FILE)
    clf = joblib.load(MODEL_FILE)
    print(f"[💾] Memory Loaded: Recovered {len(normal_traffic)} patterns from disk.")
else:
    print("[🌱] No memory found. Generating initial 500 baseline samples...")
    np.random.seed(42)
    lengths = np.random.randint(10, 150, 500)      
    symbols = np.random.randint(0, 3, 500)         
    entropies = np.random.uniform(1.0, 3.0, 500)  
    keywords = np.zeros(500) 
    
    normal_traffic = np.column_stack((lengths, symbols, entropies, keywords))
    
    clf = IsolationForest(contamination=0.01, random_state=42)
    clf.fit(normal_traffic)
    
    np.save(DATA_FILE, normal_traffic)
    joblib.dump(clf, MODEL_FILE)
    print(f"[✔] Initial Model Trained and SAVED to disk.")

def extract_features(payload: str):
    p_lower = payload.lower()
    length = len(payload)
    special_chars = sum(not c.isalnum() and not c.isspace() for c in payload)
    
    dangerous_keywords = ['union', 'select', 'insert', 'drop', 'script', 'admin', 'sleep', 'waitfor', 'delay']
    keyword_count = sum(1 for word in dangerous_keywords if word in p_lower) * 20
    
    prob = [float(payload.count(c)) / length for c in dict.fromkeys(list(payload))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob]) if length > 0 else 0
    
    return np.array([[length, special_chars, entropy, keyword_count]])

@app.post("/api/v1/ml/predict")
async def predict_anomaly(req: Request):
    data = await req.json()
    payload = data.get("payload", "")
    
    features = extract_features(payload)
    prediction = clf.predict(features) 
    score = clf.decision_function(features)[0] 
    
    is_anomaly = bool(prediction[0] == -1)
    confidence = float(abs(score) * 200) if is_anomaly else 0
    
    print(f"\n[🔍] ML Analyzing Payload: Length={features[0][0]}, Symbols={features[0][1]}, Entropy={features[0][2]:.2f}, Keywords={int(features[0][3] / 20)}")
    print(f"[🧠] Verdict: {'☠️ ANOMALY' if is_anomaly else '✅ NORMAL'} (Score: {score:.3f})")

    return {
        "is_malicious": is_anomaly,
        "confidence": min(round(confidence, 2), 99.99),
        "engine": "IsolationForest-ZeroDay",
        "features_extracted": {
            "length": int(features[0][0]),
            "special_chars": int(features[0][1]),
            "entropy": round(features[0][2], 2),
            "keyword_count": int(features[0][3])
        }
    }

@app.post("/api/v1/ml/feedback")
async def update_model(req: Request):
    global normal_traffic, clf
    data = await req.json()
    new_payload = data.get("payload", "")
    
    if new_payload:
        new_features = extract_features(new_payload)
        
        exists = any(np.allclose(new_features, row, atol=1e-5) for row in normal_traffic)
        
        if exists:
            print(f"[ℹ] Feedback Ignored: Pattern already exists in training set.")
            return {"status": "ignored", "message": "Pattern already known."}
        
        normal_traffic = np.vstack([normal_traffic, new_features])
        clf.fit(normal_traffic)
        
        np.save(DATA_FILE, normal_traffic)
        joblib.dump(clf, MODEL_FILE)
        
        print(f"\n[🔄] FEEDBACK RECEIVED: Model updated and SAVED to disk.")
        print(f"[📊] Training set size: {len(normal_traffic)} samples.")
        return {"status": "success", "message": "Model updated and persisted."}
    
    return {"status": "error", "message": "No payload provided."}

@app.post("/api/v1/ml/swarm_feedback")
async def swarm_update(req: Request):
    global normal_traffic, clf
    data = await req.json()
    features = data.get("features")
    
    if features:
        try:
            new_array = np.array([[
                float(features.get("length", 0)),
                float(features.get("special_chars", 0)),
                float(features.get("entropy", 0.0)),
                float(features.get("keyword_count", 0))
            ]])
            
            normal_traffic = np.vstack([normal_traffic, new_array])
            clf.fit(normal_traffic)
            
            np.save(DATA_FILE, normal_traffic)
            joblib.dump(clf, MODEL_FILE)
            
            print(f"\n[🐝] SWARM ASSIMILATION: ML Engine learned a new Zero-Day pattern.")
            print(f"[📊] Training set size increased to: {len(normal_traffic)} samples.")
            return {"status": "success", "message": "Swarm features integrated."}
        except Exception as e:
            print(f"[⚠️] Swarm ML Error: {str(e)}")
            return {"status": "error", "message": str(e)}
            
    return {"status": "failed", "message": "No features provided"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")