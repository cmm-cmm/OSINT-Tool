"""
Social Media Recon — modular sub-package.

Each platform lives in its own module; this __init__ re-exports
all public functions for backward compatibility with code that does
  `from modules.social_recon import facebook_recon, ...`
"""
# Re-export from individual platform modules (new modular structure)
from modules.social.tiktok import tiktok_recon, print_tiktok_results
from modules.social.twitter import twitter_recon, print_twitter_results
from modules.social.instagram import instagram_recon as instagram_recon_social, print_instagram_results
from modules.social.reddit import reddit_recon, print_reddit_results
from modules.social.analysis import detect_suspicious_account, print_account_analysis

# Facebook remains in its own module (complex, needs full social_recon imports)
from modules.social.facebook import facebook_recon, print_facebook_results

__all__ = [
    # Facebook
    "facebook_recon",
    "print_facebook_results",
    # TikTok
    "tiktok_recon",
    "print_tiktok_results",
    # Twitter
    "twitter_recon",
    "print_twitter_results",
    # Instagram (social context, distinct from instagram_recon module)
    "instagram_recon_social",
    "print_instagram_results",
    # Reddit
    "reddit_recon",
    "print_reddit_results",
    # Account analysis
    "detect_suspicious_account",
    "print_account_analysis",
]
