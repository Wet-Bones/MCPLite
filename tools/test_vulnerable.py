# test_vulnerable.py
import subprocess
import pickle

# Issue 1: Hardcoded password (B105)
API_KEY = "sk_live_1234567890abcdef"

# Issue 2: Shell injection risk (B605)
subprocess.run("ls -la", shell=True)

# Issue 3: Unsafe deserialization (B301)
def load_data(data):
    return pickle.loads(data)  # Dangerous!