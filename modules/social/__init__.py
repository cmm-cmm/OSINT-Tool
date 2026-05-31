"""
Social Media Recon — modular sub-package.

Each platform lives in its own module; this __init__ re-exports
all public functions for backward compatibility.
"""
from modules.social.facebook import (
    facebook_recon,
    print_facebook_results,
)
from modules.social.tiktok import (
    tiktok_recon,
    print_tiktok_results,
)
from modules.social.instagram import (
    instagram_recon as instagram_recon_social,
    print_instagram_results,
)
from modules.social.twitter import (
    twitter_recon,
    print_twitter_results,
)
from modules.social.reddit import (
    reddit_recon,
    print_reddit_results,
)
from modules.social.analysis import (
    detect_suspicious_account,
    print_account_analysis,
)

__all__ = [
    "facebook_recon", "print_facebook_results",
    "tiktok_recon", "print_tiktok_results",
    "instagram_recon_social", "print_instagram_results",
    "twitter_recon", "print_twitter_results",
    "reddit_recon", "print_reddit_results",
    "detect_suspicious_account", "print_account_analysis",
]
