from __future__ import annotations
import argparse
import importlib.util
import json
import platform
import sys
from . import APP_NAME, __version__
from .util import data_root


def doctor() -> int:
    from .engine import discover_plugins
    report = {"application": APP_NAME, "application_version": __version__, "python": sys.version, "platform": platform.platform(),
              "data_directory": str(data_root()), "tkinter_importable": bool(importlib.util.find_spec("tkinter")),
              "volatility_importable": bool(importlib.util.find_spec("volatility3")),
              "pdf_export_available": bool(importlib.util.find_spec("reportlab")),
              "safe_xml_available": bool(importlib.util.find_spec("defusedxml")),
              "optional_dependencies": {name: bool(importlib.util.find_spec(name)) for name in ("yara", "capstone", "Crypto", "Evtx")},
              "notes": "Import checks do not test a display server or validate a real memory image."}
    okay = report["tkinter_importable"] and report["volatility_importable"] and report["pdf_export_available"] and report["safe_xml_available"]
    if report["volatility_importable"]:
        try:
            catalog = discover_plugins()
            report.update(volatility_version=catalog["version"], available_plugins=len(catalog["plugins"]),
                          unavailable_plugins=catalog["unavailable"])
        except Exception as exc:
            report["discovery_error"] = str(exc)
            okay = False
    print(json.dumps(report, indent=2))
    return 0 if okay else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Test Subject 007 - local Volatility 3 workbench")
    parser.add_argument("--doctor", action="store_true", help="Check imports and installed plugin discovery; no GUI")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--case", help="Open an existing case directory")
    policy=parser.add_mutually_exclusive_group()
    policy.add_argument("--online-symbols",action="store_true",help="Allow approved symbol downloads; save policy before launch")
    policy.add_argument("--offline-symbols",action="store_true",help="Use locally supplied symbols only")
    parser.add_argument("--fresh-settings",action="store_true",help="Back up app settings and recent-location preferences, then use defaults; never touches cases or evidence")
    args = parser.parse_args()
    if args.fresh_settings:
        from .util import utc_now
        import uuid
        stamp=utc_now().replace(":", "").replace("+", "_")+"-"+uuid.uuid4().hex[:6]
        for name in ("settings.json","recent-locations.json"):
            path=data_root()/name
            if path.is_file():
                backup=path.with_name(path.stem+"-backup-"+stamp+".json")
                path.rename(backup)
                print("Settings preserved at: "+str(backup))
    if args.online_symbols or args.offline_symbols:
        from .util import atomic_json, utc_now
        from pathlib import Path
        import shutil
        settings_file=data_root()/"settings.json"
        data={}
        if settings_file.exists():
            data=json.loads(settings_file.read_text(encoding="utf-8"))
            if not isinstance(data,dict):
                parser.error("Settings must be a JSON object. Preserve and inspect the file.")
            suffix=utc_now().replace(":","").replace("+", "_")
            shutil.copy2(settings_file,settings_file.with_name("settings-backup-"+suffix+".json"))
        data["offline"]=bool(args.offline_symbols)
        atomic_json(settings_file,data)
    if args.doctor:
        raise SystemExit(doctor())
    try:
        from .gui import launch
        launch(args.case)
    except ImportError as exc:
        print(f"Cannot load the desktop interface: {exc}. On Debian/Ubuntu/Kali install python3-tk.", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
