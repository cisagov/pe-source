"""The pe_source library."""
# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.
# Standard Python Libraries
import logging
from logging.handlers import RotatingFileHandler

from ._version import __version__  # noqa: F401

__all__ = ["cybersixgill", "shodan"]
CENTRAL_LOGGING_FILE = "pe_reports_logging.log"
DEBUG = False

# Setup Logging
"""Set up logging and call the run_pe_script function."""
if DEBUG is True:
    level = "DEBUG"
else:
    level = "INFO"

# Logging will rotate at 2GB
logging.basicConfig(
    filename=CENTRAL_LOGGING_FILE,
    filemode="a",
    format="%(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level=level,
)
