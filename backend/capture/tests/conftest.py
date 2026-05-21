import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import sys

def pytest_runtest_setup(item):
    full = "backend.detection.ml.ensemble_correlator"
    bare = "ensemble_correlator"
    if full in sys.modules:
        sys.modules[bare] = sys.modules[full]
    elif bare in sys.modules:
        sys.modules[full] = sys.modules[bare]
