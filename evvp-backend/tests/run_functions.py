"""Runs pytest-style ``test_*`` functions without pytest (so tests work on a bare Python install).
If pytest is installed, just use ``pytest`` instead."""
import importlib, inspect, pkgutil, sys, traceback, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests
passed = failed = 0
for m in pkgutil.iter_modules(tests.__path__):
    if not m.name.startswith("test_"):
        continue
    mod = importlib.import_module(f"tests.{m.name}")
    for name, fn in inspect.getmembers(mod, inspect.isfunction):
        if name.startswith("test_") and fn.__module__ == mod.__name__ and not inspect.signature(fn).parameters:
            try:
                fn(); passed += 1
            except Exception:
                failed += 1; print(f"FAIL {m.name}.{name}"); traceback.print_exc()
print(f"function tests: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
