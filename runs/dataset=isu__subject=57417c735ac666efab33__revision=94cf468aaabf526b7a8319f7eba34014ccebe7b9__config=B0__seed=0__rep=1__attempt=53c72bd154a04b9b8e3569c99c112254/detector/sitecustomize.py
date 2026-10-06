"""Read-only crash diagnostics loaded by Python before Slither/MV-Scan."""
import sys


def _describe(value):
    try:
        return f"type={type(value).__module__}.{type(value).__name__} repr={value!r}"
    except Exception as exc:
        return f"type={type(value).__module__}.{type(value).__name__} repr_error={exc!r}"


def _hook(exc_type, exc, tb):
    print("[mvscan-diagnostic] uncaught", exc_type.__name__, repr(exc), file=sys.stderr)
    current = tb
    while current is not None:
        frame = current.tb_frame
        name = frame.f_code.co_name
        if name in {"_origins_for_operand", "_locations_for_operand", "_analyze_function_influence"}:
            print(f"[mvscan-diagnostic] frame={name}", file=sys.stderr)
            for key in ("operand", "argt", "arguments", "ir", "fn", "bid", "ir_index"):
                if key in frame.f_locals:
                    print(f"[mvscan-diagnostic] {key} {_describe(frame.f_locals[key])}", file=sys.stderr)
        current = current.tb_next
    sys.__excepthook__(exc_type, exc, tb)


sys.excepthook = _hook
