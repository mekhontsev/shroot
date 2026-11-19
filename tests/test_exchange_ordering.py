"""Check AArch64 handoff outcomes with herd7; no kernel or device timing model."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


MODELS = Path(__file__).with_name("litmus")
# Remove exactly one ordering edge in each negative control. Changing the
# wake algorithm or losing a queued wake is covered by the C protocol model.
WEAKEN = {
    "ExchangePark": ("LDAR W4,[X2]", "LDR W4,[X2]"),
    "ExchangePayload": ("LDAR W4,[X1]", "LDR W4,[X1]"),
}


def verify(command):
    with tempfile.TemporaryDirectory(prefix="shroot-herd-") as tmp:
        cases = {}
        for name in ("ExchangePark", "NativePark", "NativeClaimPark", "RetireParkLSE",
                     "RetireParkExclusive", "ExchangePayload"):
            path = MODELS / (name + ".litmus")
            cases[path] = "Never"
            if name in WEAKEN:
                source = path.read_text()
                before, after = WEAKEN[name]
                header = "AArch64 " + name + "\n"
                if not source.startswith(header) or before not in source:
                    raise ValueError(f"{name}: negative control no longer matches")
                weak = Path(tmp) / (name + "Weak.litmus")
                weak.write_text(source.replace(header, "AArch64 " + weak.stem + "\n", 1)
                                .replace(before, after, 1))
                cases[weak] = "Sometimes"
        result = subprocess.run([*command, *cases], capture_output=True, text=True, timeout=90)
        observed = re.findall(r"^Observation (\w+) (Never|Sometimes|Always) (\d+) (\d+)$",
                              result.stdout, re.MULTILINE)
        expected = [(path.stem, outcome) for path, outcome in cases.items()]
        # A forbidden outcome is not evidence if the filter eliminated every
        # execution, e.g. if a supposed successful CAS cannot publish.
        if (result.returncode or result.stderr.strip()
                or sorted((n, o) for n, o, _, _ in observed) != sorted(expected)
                or any(int(neg) == 0 or (int(pos) > 0) != (o == "Sometimes")
                       for _, o, pos, neg in observed)):
            raise SystemExit(result.stdout + result.stderr + f"\nExpected observations: {expected}")
        for name, outcome, pos, neg in observed:
            print(f"{name}: {outcome} (positive={pos}, negative={neg})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    frontend = parser.add_mutually_exclusive_group()
    frontend.add_argument("--herd", default="herd7", help="herdtools7 executable")
    frontend.add_argument("--jerd", type=Path, help="upstream jerd.js bundle (requires Node.js)")
    args = parser.parse_args()
    verify(["node", MODELS / "run_jerd.cjs", args.jerd] if args.jerd
           else [args.herd, "-model", "aarch64.cat"])
