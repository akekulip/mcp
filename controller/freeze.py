"""Recompute ``controller/infer.py``'s hash and rewrite ``module_sha256`` in frozen.yaml.

Usage: ``python3 controller/freeze.py`` (run after the final edit of infer.py).
"""
import logging
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from controller.infer import FROZEN_CONFIG_PATH, module_hash

logger = logging.getLogger(__name__)


def freeze(path: str = FROZEN_CONFIG_PATH) -> str:
    """Write the current module hash into ``path`` and return it."""
    digest = module_hash()
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    new_text, n = re.subn(r"^module_sha256:.*$", "module_sha256: %s" % digest, text, flags=re.M)
    if n == 0:
        new_text = text.rstrip("\n") + "\nmodule_sha256: %s\n" % digest
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new_text)
    logger.info("frozen infer.py sha256=%s -> %s", digest, path)
    return digest


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    sys.stdout.write(freeze() + "\n")
