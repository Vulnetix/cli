import re

# Gemini keys are ordinary Google API keys
GEMINI_KEY = re.compile(r"AIza[0-9A-Za-z_\-]{35}")
