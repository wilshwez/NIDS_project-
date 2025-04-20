import subprocess
import sys

auth_process = subprocess.run([sys.executable, "auth.py"])

if auth_process.returncode == 0:  # If authentication succeeds
    subprocess.run([sys.executable, "gui.py"])
else:
    print("Authentication failed. Exiting...")
