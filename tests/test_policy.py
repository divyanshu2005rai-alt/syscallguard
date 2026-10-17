# test_policy.py: unprivileged unit tests for guard/policy.py. Run anywhere:
#   python3 -m unittest tests/test_policy.py
# Track: G (Guard runtime & bridge)
# Contract: ARCHITECTURE.md Contract 2 (policy file).
#
# TODO (M1 Tagging):
#   - valid example policy parses (with a temp protect file)
#   - bad mode, relative path, missing path, bad CIDR -> exit 2
#   - --mode override wins; v4/v6 allow split is correct
