#!/usr/bin/env python3
"""List unittest identities for CTest without running fixtures or duplicating cases."""
import importlib.util
from pathlib import Path
import sys
import unittest


def cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        else:
            yield item.id().split('.', 1)[1]


if __name__ == '__main__':
    source = Path(sys.argv[1]).resolve(strict=True)
    spec = importlib.util.spec_from_file_location('_shroot_discovery', source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    print('\n'.join(cases(unittest.defaultTestLoader.loadTestsFromModule(module))))
