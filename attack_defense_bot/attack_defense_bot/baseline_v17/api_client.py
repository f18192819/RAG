"""Reuse external credentials and shared infrastructure."""
try:
    from ..api_client import *
except ImportError:
    from api_client import *
