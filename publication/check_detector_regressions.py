#!/usr/bin/env python3
"""Run detector unit tests using only the pinned Linux runtime and stdlib fixtures."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NAMES = ["test_exact_witness_pairs.py", "test_freeze_repairs.py", "test_root_seeding.py", "test_rmw_pairing.py"]
HARNESS = """
import sys, types, inspect
from contextlib import ExitStack
from unittest.mock import patch
count = 0
class MonkeyPatch:
    def __init__(self, stack): self.stack = stack
    def setattr(self, obj, name, value):
        self.stack.enter_context(patch.object(obj, name, value))
for filename, source in SOURCES.items():
    name = filename.removesuffix(".py")
    module = types.ModuleType(name)
    module.__file__ = "/mnt/mvscan-smoke/tests/" + filename
    sys.modules[name] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    for key, function in list(module.__dict__.items()):
        if not (key.startswith("test_") and callable(function)): continue
        with ExitStack() as stack:
            parameters = list(inspect.signature(function).parameters)
            if not parameters: function()
            elif parameters == ["monkeypatch"]: function(MonkeyPatch(stack))
            else: raise RuntimeError("Unsupported test fixture: " + key)
        count += 1
assert count == 13
print("Frozen-runtime detector regression tests passed:", count)
"""

def main():
    if sys.platform != "linux":
        raise SystemExit("Requires Linux and the restored frozen runtime; see README.md.")
    runtime = ROOT / "environment/oci-rootfs"
    if not runtime.is_dir():
        raise SystemExit("First run: python3.10 publication/restore.py runtime --download")
    sources = {name: (ROOT / "mvscan-smoke/tests" / name).read_text() for name in NAMES}
    script = "SOURCES = " + repr(sources) + "\n" + HARNESS
    command = ["bwrap", "--unshare-all", "--die-with-parent", "--ro-bind", str(runtime), "/",
               "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/mnt",
               "--ro-bind", str(ROOT / "mvscan-smoke"), "/mnt/mvscan-smoke", "--clearenv",
               "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
               "--setenv", "PYTHONPATH", "/mnt/mvscan-smoke", "/usr/local/bin/python", "-"]
    subprocess.run(command, input=script, text=True, check=True)

if __name__ == "__main__":
    main()
