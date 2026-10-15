import os
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(str(Path(__file__).resolve().parent / "lib"))
sys.path.append("/opt/app/lib")
sys.path.insert(0, sys.prefix)
print(sys.path[0])
