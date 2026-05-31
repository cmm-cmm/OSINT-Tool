"""
Tests for modules/social/ — shim sub-package.

Each platform module (facebook, tiktok, instagram, twitter, reddit) is a
one-line re-export from modules.social_recon.  These tests verify that:
  1. The shims are importable without error.
  2. They re-export the correct callables.
  3. The top-level modules/social/__init__.py re-exports everything.
  4. The analysis shim also re-exports correctly.
"""
import pytest
from unittest.mock import patch, MagicMock


class TestFacebookShim:
    def test_importable(self):
        from modules.social import facebook as fb_mod
        assert fb_mod is not None

    def test_facebook_recon_exported(self):
        from modules.social.facebook import facebook_recon
        assert callable(facebook_recon)

    def test_print_facebook_results_exported(self):
        from modules.social.facebook import print_facebook_results
        assert callable(print_facebook_results)

    def test_all_defined(self):
        import modules.social.facebook as mod
        assert hasattr(mod, "__all__")
        assert "facebook_recon" in mod.__all__
        assert "print_facebook_results" in mod.__all__

    def test_delegates_to_social_recon(self):
        """Verify facebook_recon comes from social_recon, not a new implementation."""
        from modules.social.facebook import facebook_recon
        from modules.social_recon import facebook_recon as original
        assert facebook_recon is original


class TestTikTokShim:
    def test_importable(self):
        import modules.social.tiktok
        assert modules.social.tiktok is not None

    def test_tiktok_recon_exported(self):
        from modules.social.tiktok import tiktok_recon
        assert callable(tiktok_recon)

    def test_print_tiktok_results_exported(self):
        from modules.social.tiktok import print_tiktok_results
        assert callable(print_tiktok_results)

    def test_all_defined(self):
        import modules.social.tiktok as mod
        assert hasattr(mod, "__all__")
        assert "tiktok_recon" in mod.__all__
        assert "print_tiktok_results" in mod.__all__

    def test_delegates_to_social_recon(self):
        from modules.social.tiktok import tiktok_recon
        from modules.social_recon import tiktok_recon as original
        assert tiktok_recon is original


class TestInstagramShim:
    def test_importable(self):
        import modules.social.instagram
        assert modules.social.instagram is not None

    def test_instagram_recon_exported(self):
        from modules.social.instagram import instagram_recon
        assert callable(instagram_recon)

    def test_print_instagram_results_exported(self):
        from modules.social.instagram import print_instagram_results
        assert callable(print_instagram_results)

    def test_all_defined(self):
        import modules.social.instagram as mod
        assert hasattr(mod, "__all__")
        assert "instagram_recon" in mod.__all__
        assert "print_instagram_results" in mod.__all__

    def test_delegates_to_social_recon(self):
        from modules.social.instagram import instagram_recon
        from modules.social_recon import instagram_recon as original
        assert instagram_recon is original


class TestTwitterShim:
    def test_importable(self):
        import modules.social.twitter
        assert modules.social.twitter is not None

    def test_twitter_recon_exported(self):
        from modules.social.twitter import twitter_recon
        assert callable(twitter_recon)

    def test_print_twitter_results_exported(self):
        from modules.social.twitter import print_twitter_results
        assert callable(print_twitter_results)

    def test_all_defined(self):
        import modules.social.twitter as mod
        assert hasattr(mod, "__all__")
        assert "twitter_recon" in mod.__all__
        assert "print_twitter_results" in mod.__all__

    def test_delegates_to_social_recon(self):
        from modules.social.twitter import twitter_recon
        from modules.social_recon import twitter_recon as original
        assert twitter_recon is original


class TestRedditShim:
    def test_importable(self):
        import modules.social.reddit
        assert modules.social.reddit is not None

    def test_reddit_recon_exported(self):
        from modules.social.reddit import reddit_recon
        assert callable(reddit_recon)

    def test_print_reddit_results_exported(self):
        from modules.social.reddit import print_reddit_results
        assert callable(print_reddit_results)

    def test_all_defined(self):
        import modules.social.reddit as mod
        assert hasattr(mod, "__all__")
        assert "reddit_recon" in mod.__all__
        assert "print_reddit_results" in mod.__all__

    def test_delegates_to_social_recon(self):
        from modules.social.reddit import reddit_recon
        from modules.social_recon import reddit_recon as original
        assert reddit_recon is original


class TestAnalysisShim:
    def test_importable(self):
        import modules.social.analysis
        assert modules.social.analysis is not None

    def test_detect_suspicious_account_exported(self):
        from modules.social.analysis import detect_suspicious_account
        assert callable(detect_suspicious_account)

    def test_print_account_analysis_exported(self):
        from modules.social.analysis import print_account_analysis
        assert callable(print_account_analysis)

    def test_all_defined(self):
        import modules.social.analysis as mod
        assert hasattr(mod, "__all__")
        assert "detect_suspicious_account" in mod.__all__
        assert "print_account_analysis" in mod.__all__

    def test_delegates_to_social_recon(self):
        from modules.social.analysis import detect_suspicious_account
        from modules.social_recon import detect_suspicious_account as original
        assert detect_suspicious_account is original


class TestSocialPackageInit:
    def test_package_importable(self):
        import modules.social
        assert modules.social is not None

    def test_facebook_recon_in_package(self):
        from modules.social import facebook_recon
        assert callable(facebook_recon)

    def test_print_facebook_results_in_package(self):
        from modules.social import print_facebook_results
        assert callable(print_facebook_results)

    def test_tiktok_recon_in_package(self):
        from modules.social import tiktok_recon
        assert callable(tiktok_recon)

    def test_print_tiktok_results_in_package(self):
        from modules.social import print_tiktok_results
        assert callable(print_tiktok_results)

    def test_instagram_recon_social_in_package(self):
        from modules.social import instagram_recon_social
        assert callable(instagram_recon_social)

    def test_print_instagram_results_in_package(self):
        from modules.social import print_instagram_results
        assert callable(print_instagram_results)

    def test_twitter_recon_in_package(self):
        from modules.social import twitter_recon
        assert callable(twitter_recon)

    def test_print_twitter_results_in_package(self):
        from modules.social import print_twitter_results
        assert callable(print_twitter_results)

    def test_reddit_recon_in_package(self):
        from modules.social import reddit_recon
        assert callable(reddit_recon)

    def test_print_reddit_results_in_package(self):
        from modules.social import print_reddit_results
        assert callable(print_reddit_results)

    def test_detect_suspicious_account_in_package(self):
        from modules.social import detect_suspicious_account
        assert callable(detect_suspicious_account)

    def test_print_account_analysis_in_package(self):
        from modules.social import print_account_analysis
        assert callable(print_account_analysis)

    def test_all_list_complete(self):
        import modules.social
        expected = [
            "facebook_recon", "print_facebook_results",
            "tiktok_recon", "print_tiktok_results",
            "instagram_recon_social", "print_instagram_results",
            "twitter_recon", "print_twitter_results",
            "reddit_recon", "print_reddit_results",
            "detect_suspicious_account", "print_account_analysis",
        ]
        for name in expected:
            assert name in modules.social.__all__, f"{name!r} missing from __all__"

    def test_package_functions_are_same_as_submodule(self):
        """All re-exports in __init__ should be the same object as their source."""
        from modules.social import facebook_recon as pkg_fb
        from modules.social.facebook import facebook_recon as mod_fb
        assert pkg_fb is mod_fb

    def test_instagram_recon_social_alias(self):
        """instagram_recon_social in __init__ is instagram_recon from the shim."""
        from modules.social import instagram_recon_social
        from modules.social.instagram import instagram_recon
        assert instagram_recon_social is instagram_recon


class TestSharedModule:
    def test_shared_importable(self):
        import modules.social._shared
        assert modules.social._shared is not None

    def test_shared_is_docstring_only(self):
        import modules.social._shared as shared
        # The _shared.py is just a docstring shim
        assert shared.__doc__ is not None
        # No public names defined
        public_names = [n for n in dir(shared) if not n.startswith("_")]
        assert len(public_names) == 0
