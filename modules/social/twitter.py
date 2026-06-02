"""Twitter/X OSINT module — delegates to social_recon for backward compatibility."""
from modules.social_recon import twitter_recon, print_twitter_results

__all__ = ["twitter_recon", "print_twitter_results"]
