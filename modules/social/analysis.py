"""Social account analysis — delegates to social_recon for backward compatibility."""
from modules.social_recon import detect_suspicious_account, print_account_analysis

__all__ = ["detect_suspicious_account", "print_account_analysis"]
