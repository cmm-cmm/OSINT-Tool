"""Reddit OSINT module — delegates to social_recon for backward compatibility."""
from modules.social_recon import reddit_recon, print_reddit_results

__all__ = ["reddit_recon", "print_reddit_results"]
