"""Entry point for: python -m janus.adapters.external"""
import sys
import warnings

warnings.filterwarnings("ignore", category=RuntimeWarning, module="runpy")

from janus.adapters.external import main  # noqa: E402

sys.exit(main())
