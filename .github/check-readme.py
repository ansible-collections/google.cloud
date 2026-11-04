#!/usr/bin/env python
"""Checks consistency between plugins/modules/ directory and README.md.

- Files in filesystem not mentioned in README
- Modules mentioned in README with no corresponding file
"""

from __future__ import annotations

import logging
import pathlib
import re
import sys
import typing as T

EXCEPTIONS: set[str] = {
    "gcp_cred_file",
    "gcp_project",
}


class ColorFormatter(logging.Formatter):
    RESET: T.ClassVar = "\033[0m"
    COLORS: T.ClassVar = {
        logging.DEBUG: "\033[36m",
        logging.INFO: "\033[32m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[1;31m",
    }

    def __init__(self, fmt: str, use_color: bool = True) -> None:
        super().__init__(fmt)
        self.use_color: bool = use_color and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        message: str = super().format(record)
        if not self.use_color:
            return message
        color: str = self.COLORS.get(record.levelno, "")
        return f"{color}{message}{self.RESET}" if color else message


def build_logger() -> logging.Logger:
    logger: logging.Logger = logging.getLogger("check-readme")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    handler: logging.Handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter("%(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def main() -> int:
    root_dir: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent
    readme: pathlib.Path = root_dir / "README.md"
    modules_dir: pathlib.Path = root_dir / "plugins" / "modules"
    logger: logging.Logger = build_logger()

    failures: int = 0

    logger.info("Checking consistency between plugins/modules/ and README.md")

    # ========================================================================
    # CHECK 1: Files in filesystem that are missing from README
    # ========================================================================
    logger.warning("[CHECK 1] Modules in filesystem missing from README.md")

    readme_text: str = readme.read_text(encoding="utf-8")

    check1_failures: int = 0
    for module_path in sorted(modules_dir.glob("*.py")):
        modname: str = module_path.stem
        if modname in readme_text:
            logger.info("  Checking %s... OK", modname)
        else:
            logger.error("  Checking %s... MISSING", modname)
            check1_failures += 1

    if check1_failures > 0:
        logger.error("Found %d modules missing from README", check1_failures)
        failures += check1_failures
    else:
        logger.info("All filesystem modules are documented")

    # ========================================================================
    # CHECK 2: Modules mentioned in README with no corresponding file
    # ========================================================================
    logger.warning("[CHECK 2] Modules in README.md with no corresponding file")

    check2_failures: int = 0
    referenced_modules: list[str] = sorted(set(re.findall(r"gcp_\w+", readme_text)))
    for modname in referenced_modules:
        if modname in EXCEPTIONS:
            continue

        modfile: pathlib.Path = modules_dir / f"{modname}.py"
        if modfile.is_file():
            logger.info("  Checking %s... OK", modname)
        else:
            logger.error("  Checking %s... MISSING", modname)
            check2_failures += 1

    if check2_failures > 0:
        logger.error("Found %d referenced modules with no file", check2_failures)
        failures += check2_failures
    else:
        logger.info("All referenced modules have files")

    logger.info(
        "============================================================================"
    )
    if failures > 0:
        logger.error("Summary: Found %d inconsistencies", failures)
    else:
        logger.info("Summary: All checks passed!")

    return failures


if __name__ == "__main__":
    sys.exit(main())
