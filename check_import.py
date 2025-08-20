# check_import.py
# Sneltest om te zien of Python je pakket kan importeren.

import sys
print("Python path:", sys.path)
try:
    import threathawk
    from threathawk import server
    print("✅ Import OK: 'threathawk' en 'threathawk.server' aanwezig.")
except Exception as e:
    print("❌ Import FOUT:", repr(e))
    raise
