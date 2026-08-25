#!/usr/bin/env python

import difflib
import glob
import logging
import os
import sys

import yaml

ROOT_DIR: str = os.path.realpath(os.path.join(os.path.dirname(sys.argv[0]), ".."))
META_DIR: str = os.path.join(ROOT_DIR, "meta")
MODULE_DIR: str = os.path.join(ROOT_DIR, "plugins", "modules")


def check_tombstones(module_files, meta):
    "Makes sure there aren't any missing tombstones"

    logging.info("Comparing existing tombstones vs action groups")
    tombstones = []
    for plugin, routing in meta["plugin_routing"]["modules"].items():
        if routing.get("tombstone", False):
            tombstones.append(plugin)
    tombstones.sort()

    meta_modules = meta["action_groups"]["gcp"]
    meta_modules.sort()

    warnings = []
    # if a module is present in action groups but missing from the filesystem
    # then it means it should be tombstoned
    for module in meta_modules:
        if module not in module_files:
            warnings.append(
                ValueError(
                    f"{module} is present in runtime meta but missing "
                    "from file system, needs tombstone"
                )
            )

    return warnings


def check_action_groups(module_files, meta):
    "Makes sure there aren't any missing modules from action_groups"

    logging.info("Comparing existing module files vs action groups")

    meta_modules = meta["action_groups"]["gcp"]

    warnings = []
    # if a module is present in action groups but missing from the filesystem
    # then it means it should be tombstoned
    for module in module_files:
        if module not in meta_modules:
            warnings.append(
                ValueError(
                    f"{module} file is present in filesystem meta but missing "
                    "entry in action_groups"
                )
            )

    return warnings


def diff_action_groups(module_files, meta):
    "Makes sure action groups defined in meta/runtime.yml match existing files"

    lnbr_modules = [f"{m}\n" for m in module_files]  # for difflib's sake
    meta_modules = [f"{m}\n" for m in meta["action_groups"]["gcp"]]
    meta_modules.sort()

    diff = list(
        difflib.unified_diff(
            lnbr_modules,
            meta_modules,
            fromfile="plugins/modules/*.py",
            tofile="meta/runtime.yml",
        )
    )
    sys.stdout.writelines(diff)


def main():
    logging.basicConfig(level=logging.INFO)
    logging.info("Loading plugin filenames from {}".format(MODULE_DIR))
    warnings = []
    module_files = []
    for fn in glob.glob(os.path.join(MODULE_DIR, "*.py")):
        module_files.append(os.path.basename(os.path.splitext(fn)[0]))
    module_files.sort()

    logging.info("Loading runtime meta from {}/runtime.yml".format(META_DIR))
    try:
        meta = yaml.safe_load(open(os.path.join(META_DIR, "runtime.yml")).read())
    except Exception as e:
        logging.error(e)
        raise

    warnings.extend(check_tombstones(module_files, meta))
    warnings.extend(check_action_groups(module_files, meta))

    if len(warnings) > 0:
        for warning in warnings:
            logging.warning(warning)

        diff_action_groups(module_files, meta)

        raise RuntimeError("Encountered errors in runtime meta")

    logging.info("Done.")


if __name__ == "__main__":
    sys.exit(main())
