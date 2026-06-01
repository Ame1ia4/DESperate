import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

# test_srp_interop.py is a manual two-terminal script, not a pytest module.
collect_ignore = ["testing/test_srp_interop.py"]
