"""errors.py

cryptkeeper package errors.
"""


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
class CryptkeeperError(Exception):
    """Base class for all package errors."""


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
class KmsHelperInitializationError(CryptkeeperError):
    """An error occurred in KMS Helper initialization."""


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
class KmsAwsConnectionError(CryptkeeperError):
    """An error occurred while connecting to AWS."""