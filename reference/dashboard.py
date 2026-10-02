"""Build dashboard.html from plan.json and runs/*.json.

Usage: python3 dashboard.py

The page embeds the data files as they are, so every number it shows comes
from a file in this directory. Re-run after each reference run.
"""
import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> None:
    plan = json.load(open(os.path.join(HERE, "plan.json")))
    runs = {}
    for path in sorted(glob.glob(os.path.join(HERE, "runs", "*.json"))):
        runs[os.path.basename(path)[:-5]] = json.load(open(path))
    batteries = {}
    for path in sorted(glob.glob(os.path.join(HERE, "batteries", "*.json"))):
        battery = json.load(open(path))
        batteries[battery["id"]] = battery
    data = json.dumps({"plan": plan, "runs": runs, "batteries": batteries}, ensure_ascii=False)
    # Keep the embedded JSON from closing the script element early.
    data = data.replace("</", "<\\/")
    template = open(os.path.join(HERE, "dashboard.template.html")).read()
    out = template.replace("/*__DATA__*/", data)
    open(os.path.join(HERE, "dashboard.html"), "w").write(out)
    print(f"wrote dashboard.html ({len(out)} bytes, {len(runs)} run files)")


if __name__ == "__main__":
    main()
