"""Explicit external test host; native tests never import an application adapter."""
import importlib
import os


def adapter():
    name = os.environ.get('SHROOT_TEST_ADAPTER')
    if not name:
        raise RuntimeError('Set SHROOT_TEST_ADAPTER to an importable host adapter module')
    return importlib.import_module(name)
