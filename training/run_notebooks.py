"""
Execute training notebooks 02–04 in sequence.
Notebook 05 (ONNX) requires onnxruntime + skl2onnx — skipped if not installed.

Each notebook's code cells are extracted and executed in order via exec().
Working directory is set to the notebook's directory so relative paths work.
"""
import json
import os
import sys
import traceback
from pathlib import Path

REPO    = Path(__file__).parent.parent
NB_DIR  = REPO / "training" / "notebooks"
NOTEBOOKS = [
    "02_baseline.ipynb",
    "03_random_forest.ipynb",
    "04_isolation_forest.ipynb",
]

def run_notebook(nb_path: Path) -> bool:
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


def main() -> None:
    results = {}
    for nb_name in NOTEBOOKS:
        nb_path = NB_DIR / nb_name
        ok = run_notebook(nb_path)
        results[nb_name] = "PASS" if ok else "FAIL"
        if not ok:
            print(f"\nABORTED: {nb_name} failed. Fix before proceeding.")
            break

    print(f"\n{'='*70}")
    print("NOTEBOOK RUN SUMMARY")
    print(f"{'='*70}")
    for name, status in results.items():
        print(f"  {'✓' if status == 'PASS' else '✗'} {name}: {status}")

    try:
        import onnxruntime  # noqa: F401
        import skl2onnx     # noqa: F401
        print("\nonnxruntime + skl2onnx present — run 05_onnx_export.ipynb separately.")
    except ImportError:
        print("\nSkipped 05_onnx_export.ipynb: onnxruntime / skl2onnx not installed.")
        print("  pip install onnxruntime skl2onnx")


if __name__ == "__main__":
    main()
