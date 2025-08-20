# app.py — robuuste entrypoint voor Uvicorn op Render
import os, sys, importlib, pathlib

# 1) Zet cwd en veelgebruikte submappen op sys.path
ROOT = pathlib.Path(__file__).resolve().parent
CANDIDATES = [ROOT, ROOT / "src", ROOT / "backend", ROOT / "server", ROOT / "api", ROOT / "app"]
for p in CANDIDATES:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

def try_import():
    # Probeer de twee meest waarschijnlijke pakketten
    for mod in ("threathawk.server", "ThreatHawk.server"):
        try:
            return importlib.import_module(mod).app
        except ModuleNotFoundError:
            pass
        except Exception:
            pass

    # 2) Zoeken naar map die 'threathawk' heet (case-insensitive) en 'server.py' bevat
    target_dir = None
    for base in CANDIDATES:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            try:
                if path.is_dir() and path.name.lower() == "threathawk" and (path / "server.py").exists():
                    target_dir = path
                    break
            except Exception:
                continue
        if target_dir:
            break

    if target_dir:
        parent = str(target_dir.parent)
        if parent not in sys.path:
            sys.path.insert(0, parent)
        # Probeer import nogmaals met beide hoofdlettervarianten
        for mod in ("threathawk.server", "ThreatHawk.server"):
            try:
                return importlib.import_module(mod).app
            except ModuleNotFoundError:
                pass
            except Exception:
                pass

    # 3) Laat een duidelijke foutmelding achter
    raise ImportError(
        "Kon 'threathawk.server' niet importeren.\n"
        "- Controleer de mapnaam (exact 'threathawk' of 'ThreatHawk').\n"
        "- Zorg dat de map de file 'server.py' bevat.\n"
        "- Staat de map in een submap (bijv. 'src')? Laat dit script die map vinden of zet Root Directory op die submap.\n"
        "- Voeg zonodig een leeg '__init__.py' toe in de pakketmap."
    )

app = try_import()
