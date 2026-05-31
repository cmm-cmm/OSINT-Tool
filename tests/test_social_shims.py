"""
Tests for modules/social/* shim modules.

These modules are thin re-export wrappers that delegate to social_recon.py
for backward compatibility. Tests verify:
1. All expected symbols are importable from the shim modules
2. The shim functions are the same objects as the originals (identity check)
3. The modules/social package __init__ re-exports all public symbols
"""
import pytest
from unittest.mock import patch


class TestFacebookShim:
    def test_imports(self):
        from modules.social.facebook import facebook_recon, print_facebook_results
        assert callable(facebook_recon)
        assert callable(print_facebook_results)

    def test_all_exports(self):
        from modules.social import facebook
        assert "facebook_recon" in facebook.__all__
        assert "print_facebook_results" in facebook.__all__

    def test_same_object_as_social_recon(self):
        from modules.social.facebook import facebook_recon as shim_fn
        from modules.social_recon import facebook_recon as original_fn
        assert shim_fn is original_fn

    def test_print_same_as_social_recon(self):
        from modules.social.facebook import print_facebook_results as shim_fn
        from modules.social_recon import print_facebook_results as original_fn
        assert shim_fn is original_fn


class TestTiktokShim:
    def test_imports(self):
        from modules.social.tiktok import tiktok_recon, print_tiktok_results
        assert callable(tiktok_recon)
        assert callable(print_tiktok_results)

    def test_all_exports(self):
        from modules.social import tiktok
        assert "tiktok_recon" in tiktok.__all__
        assert "print_tiktok_results" in tiktok.__all__

    def test_same_object_as_social_recon(self):
        from modules.social.tiktok import tiktok_recon as shim_fn
        from modules.social_recon import tiktok_recon as original_fn
        assert shim_fn is original_fn


class TestInstagramShim:
    def test_imports(self):
        from modules.social.instagram import instagram_recon, print_instagram_results
        assert callable(instagram_recon)
        assert callable(print_instagram_results)

    def test_all_exports(self):
        from modules.social import instagram
        assert "instagram_recon" in instagram.__all__
        assert "print_instagram_results" in instagram.__all__

    def test_same_object_as_social_recon(self):
        from modules.social.instagram import instagram_recon as shim_fn
        from modules.social_recon import instagram_recon as original_fn
        assert shim_fn is original_fn


class TestTwitterShim:
    def test_imports(self):
        from modules.social.twitter import twitter_recon, print_twitter_results
        assert callable(twitter_recon)
        assert callable(print_twitter_results)

    def test_all_exports(self):
        from modules.social import twitter
        assert "twitter_recon" in twitter.__all__
        assert "print_twitter_results" in twitter.__all__

    def test_same_object_as_social_recon(self):
        from modules.social.twitter import twitter_recon as shim_fn
        from modules.social_recon import twitter_recon as original_fn
        assert shim_fn is original_fn


class TestRedditShim:
    def test_imports(self):
        from modules.social.reddit import reddit_recon, print_reddit_results
        assert callable(reddit_recon)
        assert callable(print_reddit_results)

    def test_all_exports(self):
        from modules.social import reddit
        assert "reddit_recon" in reddit.__all__
        assert "print_reddit_results" in reddit.__all__

    def test_same_object_as_social_recon(self):
        from modules.social.reddit import reddit_recon as shim_fn
        from modules.social_recon import reddit_recon as original_fn
        assert shim_fn is original_fn


class TestAnalysisShim:
    def test_imports(self):
        from modules.social.analysis import detect_suspicious_account, print_account_analysis
        assert callable(detect_suspicious_account)
        assert callable(print_account_analysis)

    def test_all_exports(self):
        from modules.social import analysis
        assert "detect_suspicious_account" in analysis.__all__
        assert "print_account_analysis" in analysis.__all__

    def test_same_object_as_social_recon(self):
        from modules.social.analysis import detect_suspicious_account as shim_fn
        from modules.social_recon import detect_suspicious_account as original_fn
        assert shim_fn is original_fn


class TestSocialPackageInit:
    """Test the modules/social/__init__.py re-exports."""

    def test_all_exported_symbols_importable(self):
        """Every symbol in __all__ should be importable from modules.social."""
        import modules.social as social_pkg
        for name in social_pkg.__all__:
            assert hasattr(social_pkg, name), f"Missing symbol: {name}"
            assert callable(getattr(social_pkg, name)), f"Not callable: {name}"

    def test_facebook_recon_available(self):
        from modules.social import facebook_recon
        assert callable(facebook_recon)

    def test_tiktok_recon_available(self):
        from modules.social import tiktok_recon
        assert callable(tiktok_recon)

    def test_instagram_recon_social_available(self):
        from modules.social import instagram_recon_social
        assert callable(instagram_recon_social)

    def test_twitter_recon_available(self):
        from modules.social import twitter_recon
        assert callable(twitter_recon)

    def test_reddit_recon_available(self):
        from modules.social import reddit_recon
        assert callable(reddit_recon)

    def test_detect_suspicious_account_available(self):
        from modules.social import detect_suspicious_account
        assert callable(detect_suspicious_account)

    def test_print_facebook_results_available(self):
        from modules.social import print_facebook_results
        assert callable(print_facebook_results)

    def test_print_tiktok_results_available(self):
        from modules.social import print_tiktok_results
        assert callable(print_tiktok_results)

    def test_print_instagram_results_available(self):
        from modules.social import print_instagram_results
        assert callable(print_instagram_results)

    def test_print_twitter_results_available(self):
        from modules.social import print_twitter_results
        assert callable(print_twitter_results)

    def test_print_reddit_results_available(self):
        from modules.social import print_reddit_results
        assert callable(print_reddit_results)

    def test_print_account_analysis_available(self):
        from modules.social import print_account_analysis
        assert callable(print_account_analysis)

    def test_all_list_contents(self):
        import modules.social as social_pkg
        expected = [
            "facebook_recon", "print_facebook_results",
            "tiktok_recon", "print_tiktok_results",
            "instagram_recon_social", "print_instagram_results",
            "twitter_recon", "print_twitter_results",
            "reddit_recon", "print_reddit_results",
            "detect_suspicious_account", "print_account_analysis",
        ]
        for name in expected:
            assert name in social_pkg.__all__, f"{name} missing from __all__"

    def test_init_functions_delegate_to_social_recon(self):
        """Functions from modules.social should be the same objects as in social_recon."""
        import modules.social as social_pkg
        from modules import social_recon
        pairs = [
            ("facebook_recon", "facebook_recon"),
            ("tiktok_recon", "tiktok_recon"),
            ("twitter_recon", "twitter_recon"),
            ("reddit_recon", "reddit_recon"),
            ("detect_suspicious_account", "detect_suspicious_account"),
        ]
        for social_name, recon_name in pairs:
            social_fn = getattr(social_pkg, social_name)
            recon_fn = getattr(social_recon, recon_name)
            assert social_fn is recon_fn, f"{social_name} is not the same object as social_recon.{recon_name}"
