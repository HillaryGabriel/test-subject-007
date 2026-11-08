"""Isolated Volatility adapter. Never run in the GUI interpreter.

The application discovers the installed plugin set and lets Volatility resolve
layers and symbols. No Volatility source or third-party binaries are bundled.
"""
from __future__ import annotations
import inspect
import json
import logging
import sys


def catalog() -> dict:
    import volatility3.plugins
    from volatility3 import framework
    from volatility3.framework import constants, interfaces
    from volatility3.framework.configuration import requirements

    logging.basicConfig(level=logging.ERROR)
    failures = framework.import_files(volatility3.plugins, True)
    output = []
    for name, plugin in sorted(framework.list_plugins().items()):
        options = []
        try:
            for req in plugin.get_requirements():
                item = {"name": req.name, "flag": "--" + req.name.replace("_", "-"),
                        "description": req.description or "", "required": not req.optional,
                        "default": req.default}
                if isinstance(req, requirements.BooleanRequirement):
                    item["kind"] = "bool"
                elif isinstance(req, requirements.ListRequirement):
                    item.update(kind="list", element_type=req.element_type.__name__,
                                min_elements=getattr(req, "min_elements", 0), max_elements=getattr(req, "max_elements", 0))
                elif isinstance(req, requirements.ChoiceRequirement):
                    item.update(kind="choice", choices=list(req.choices))
                elif isinstance(req, interfaces.configuration.SimpleTypeRequirement):
                    item["kind"] = "int" if isinstance(req, requirements.IntRequirement) else "str"
                    item["is_file"] = isinstance(req, requirements.URIRequirement)
                else:
                    # Layers, symbol tables and dependencies are resolved by automagic.
                    continue
                options.append(item)
            output.append({"name": name, "description": inspect.getdoc(plugin) or "",
                           "options": options})
        except Exception as exc:
            failures.append(f"{name}: requirements unavailable ({exc})")
    return {"version": constants.PACKAGE_VERSION, "plugins": output,
            "unavailable": sorted(str(x) for x in failures)}


def main() -> None:
    try:
        action = sys.argv[1]
        if action == "catalog":
            print(json.dumps(catalog(), ensure_ascii=False, default=str))
        elif action == "run":
            from volatility3.cli import CommandLine
            # Do not silently inherit a user's vol.json overrides, plugin paths,
            # output directories, or renderer settings from an unrelated session.
            class LocalCommandLine(CommandLine):
                def load_system_defaults(self, filename):
                    return [], {}
            sys.argv = ["volatility3", *sys.argv[2:]]
            LocalCommandLine().run()
        else:
            raise ValueError("Expected catalog or run.")
    except ModuleNotFoundError as exc:
        print(f"Missing analysis dependency: {exc}. Install this project with: "
              'python -m pip install -e ".[analysis]"', file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
