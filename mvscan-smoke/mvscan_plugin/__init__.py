from slither.detectors.abstract_detector import AbstractDetector
from slither.printers.abstract_printer import AbstractPrinter

from .inconsistent_state import InconsistentState


# Register MV-Scan's detector and printer classes with Slither.
def make_plugin() -> tuple[
    list[type[AbstractDetector]],
    list[type[AbstractPrinter]],
]:
    return [InconsistentState], []
