"""
Tests for modules/social/ shim package (new in this PR).

These modules are thin re-exports of functions from modules/social_recon.py
for backward compatibility. Tests verify that the public API is correctly
re-exported and callable.
"""
import pytest


class TestSocialPackageExports:
    """Verify modules/social/__init__.py re-exports the expected public API."""

    def test_facebook_recon_importable(self):
        from modules.social import facebook_recon
        assert callable(facebook_recon)

    def test_print_facebook_results_importable(self):
        from modules.social import print_facebook_results
        assert callable(print_facebook_results)

    def test_tiktok_recon_importable(self):
        from modules.social import tiktok_recon
        assert callable(tiktok_recon)

    def test_print_tiktok_results_importable(self):
        from modules.social import print_tiktok_results
        assert callable(print_tiktok_results)

    def test_instagram_recon_importable(self):
        from modules.social import instagram_recon_social
        assert callable(instagram_recon_social)

    def test_print_instagram_results_importable(self):
        from modules.social import print_instagram_results
        assert callable(print_instagram_results)

    def test_twitter_recon_importable(self):
        from modules.social import twitter_recon
        assert callable(twitter_recon)

    def test_print_twitter_results_importable(self):
        from modules.social import print_twitter_results
        assert callable(print_twitter_results)

    def test_reddit_recon_importable(self):
        from modules.social import reddit_recon
        assert callable(reddit_recon)

    def test_print_reddit_results_importable(self):
        from modules.social import print_reddit_results
        assert callable(print_reddit_results)

    def test_detect_suspicious_account_importable(self):
        from modules.social import detect_suspicious_account
        assert callable(detect_suspicious_account)

    def test_print_account_analysis_importable(self):
        from modules.social import print_account_analysis
        assert callable(print_account_analysis)

    def test_all_exports_in_dunder_all(self):
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


class TestFacebookShim:
    """Verify modules/social/facebook.py delegates to social_recon."""

    def test_facebook_recon_is_same_function(self):
        from modules.social.facebook import facebook_recon as shim_fb
        from modules.social_recon import facebook_recon as original_fb
        assert shim_fb is original_fb

    def test_print_facebook_results_is_same_function(self):
        from modules.social.facebook import print_facebook_results as shim
        from modules.social_recon import print_facebook_results as original
        assert shim is original

    def test_all_exports(self):
        import modules.social.facebook as fb_module
        assert "facebook_recon" in fb_module.__all__
        assert "print_facebook_results" in fb_module.__all__


class TestTikTokShim:
    """Verify modules/social/tiktok.py delegates to social_recon."""

    def test_tiktok_recon_is_same_function(self):
        from modules.social.tiktok import tiktok_recon as shim
        from modules.social_recon import tiktok_recon as original
        assert shim is original

    def test_all_exports(self):
        import modules.social.tiktok as tt_module
        assert "tiktok_recon" in tt_module.__all__


class TestInstagramShim:
    """Verify modules/social/instagram.py delegates to social_recon."""

    def test_instagram_recon_is_same_function(self):
        from modules.social.instagram import instagram_recon as shim
        from modules.social_recon import instagram_recon as original
        assert shim is original

    def test_all_exports(self):
        import modules.social.instagram as ig_module
        assert "instagram_recon" in ig_module.__all__


class TestTwitterShim:
    """Verify modules/social/twitter.py delegates to social_recon."""

    def test_twitter_recon_is_same_function(self):
        from modules.social.twitter import twitter_recon as shim
        from modules.social_recon import twitter_recon as original
        assert shim is original

    def test_all_exports(self):
        import modules.social.twitter as tw_module
        assert "twitter_recon" in tw_module.__all__


class TestRedditShim:
    """Verify modules/social/reddit.py delegates to social_recon."""

    def test_reddit_recon_is_same_function(self):
        from modules.social.reddit import reddit_recon as shim
        from modules.social_recon import reddit_recon as original
        assert shim is original

    def test_all_exports(self):
        import modules.social.reddit as reddit_module
        assert "reddit_recon" in reddit_module.__all__


class TestAnalysisShim:
    """Verify modules/social/analysis.py delegates to social_recon."""

    def test_detect_suspicious_account_is_same_function(self):
        from modules.social.analysis import detect_suspicious_account as shim
        from modules.social_recon import detect_suspicious_account as original
        assert shim is original

    def test_print_account_analysis_is_same_function(self):
        from modules.social.analysis import print_account_analysis as shim
        from modules.social_recon import print_account_analysis as original
        assert shim is original

    def test_all_exports(self):
        import modules.social.analysis as analysis_module
        assert "detect_suspicious_account" in analysis_module.__all__
        assert "print_account_analysis" in analysis_module.__all__
