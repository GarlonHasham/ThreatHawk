# app.py
# Entry point voor Uvicorn op Render
# Dit zorgt dat 'threathawk.server:app' altijd gevonden wordt.

try:
    from threathawk.server import app
except ModuleNotFoundError as e:
    raise ImportError(
        "Kon 'threathawk.server' niet importeren. "
        "Controleer of de map 'threathawk/' in de root van de repo staat "
        "en dat er een '__init__.py' aanwezig is (mag leeg zijn). "
        "Let op hoofd-/kleine letters: 'ThreatHawk' != 'threathawk'."
    ) from e
