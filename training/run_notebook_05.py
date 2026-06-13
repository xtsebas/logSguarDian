"""Run notebook 05 (ONNX export + parity check) standalone."""
import json
import os
import sys
import traceback
from pathlib import Path

REPO   = Path(__file__).parent.parent
NB_DIR = REPO / "training" / "notebooks"

def run_notebook(nb_path):
    print(f"\n{'='*70}")
    print(f"RUNNING: {nb_path.name}")
    print(f"{'='*70}")
    with open(nb_path, encoding="utf-8") as f:
        nb = json.load(f)
    code_cells = [c for c in nb["cells"] if c["cell_type"] == "code"]
    ns: dict = {"__name__": "__main__"}
    old_dir = os.getcwd()
    os.chdir(nb_path.parent)
    try:
        for i, cell in enumerate(code_cells):
            src = "".join(cell["source"])
            if not src.strip():
                continue
            try:
                exec(compile(src, f"<cell-{i}>", "exec"), ns)
            except AssertionError as e:
                print(f"\n[GATE FAILED] cell {i}: {e}")
                return False
            except Exception:
                print(f"\n[ERROR] cell {i}:")
                traceback.print_exc()
                return False
    finally:
        os.chdir(old_dir)
    print(f"\n[OK] {nb_path.name} completed.")
    return True

if __name__ == "__main__":
    ok = run_notebook(NB_DIR / "05_onnx_export.ipynb")
    sys.exit(0 if ok else 1)
