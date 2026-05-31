"""TikTok OSINT module — delegates to social_recon for backward compatibility."""
from modules.social_recon import tiktok_recon, print_tiktok_results

__all__ = ["tiktok_recon", "print_tiktok_results"]
