"""
Platform adapter plugins.

Each plugin translates canonical policies to platform-specific Terraform.
"""

from .base import AdapterPlugin
from .aws import AWSAdapter
from .gcp import GCPAdapter
from .azure import AzureAdapter
from .paloalto import PaloAltoAdapter
from .fortinet import FortinetAdapter
from .illumio import IllumioAdapter

__all__ = [
    "AdapterPlugin",
    "AWSAdapter",
    "GCPAdapter",
    "AzureAdapter",
    "PaloAltoAdapter",
    "FortinetAdapter",
    "IllumioAdapter",
]
