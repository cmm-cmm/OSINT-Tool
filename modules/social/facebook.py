"""Facebook OSINT module — delegates to social_recon for backward compatibility."""
from modules.social_recon import facebook_recon, print_facebook_results

__all__ = ["facebook_recon", "print_facebook_results"]
