"""
Facebook OSINT module — re-exports from core social_recon module.

The full Facebook implementation resides in modules/social_recon.py
(due to its complex multi-function structure). This shim preserves
the modular import pattern while avoiding code duplication.

Future refactor: migrate facebook_recon() fully here.
"""
# Import the full Facebook implementation from the original module
from modules.social_recon import (
    facebook_recon,
    print_facebook_results,
    _extract_og,
    _normalize_fb_id,
    _extract_numeric_id,
    _parse_og_description,
)

__all__ = [
    "facebook_recon",
    "print_facebook_results",
    "_extract_og",
    "_normalize_fb_id",
    "_extract_numeric_id",
    "_parse_og_description",
]
