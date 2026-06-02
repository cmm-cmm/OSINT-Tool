"""Instagram OSINT module — delegates to social_recon for backward compatibility."""
from modules.social_recon import instagram_recon, print_instagram_results

__all__ = ["instagram_recon", "print_instagram_results"]
