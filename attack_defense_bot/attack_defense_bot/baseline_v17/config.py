"""Reuse external credentials and shared infrastructure."""
try:
    from ..config import *
except ImportError:
    from config import *
