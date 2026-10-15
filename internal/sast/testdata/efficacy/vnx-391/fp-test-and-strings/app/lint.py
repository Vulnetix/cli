# A bare "except: pass" hides every failure; the linter rejects it.
MESSAGE = "do not write except: pass"
EXAMPLE = """
try:
    work()
except:
    pass
"""
