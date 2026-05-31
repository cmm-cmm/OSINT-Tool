"""Bot/fake account detection analysis module."""
import re
from datetime import datetime, timezone
from rich.console import Console

console = Console()


def detect_suspicious_account(profile: dict, platform: str = "unknown") -> dict:
    """
    Analyze indicators of fake/bot account based on profile metadata.

    Returns dict with suspicion_score (0-100), risk_level, indicators, positive_signals.
    """
    indicators = []
    positive_signals = []
    score = 0

    username = str(profile.get("username") or profile.get("name") or "")
    followers = profile.get("followers") or profile.get("follower_count") or 0
    following = profile.get("following") or profile.get("following_count") or 0
    bio = profile.get("bio") or profile.get("description") or profile.get("about") or ""
    verified = profile.get("verified") or False
    post_count = profile.get("post_count") or profile.get("video_count") or profile.get("tweet_count") or 0
    created_at = profile.get("created_at") or profile.get("joined") or None

    try:
        followers = int(followers)
        following = int(following)
        post_count = int(post_count)
    except (ValueError, TypeError):
        followers = following = post_count = 0

    if username:
        if re.match(r'^[a-z]{2,6}[0-9]{4,}$', username.lower()):
            score += 15
            indicators.append(f"Random username pattern: '{username}' (letters + many digits)")
        if len(username) > 20 and sum(1 for c in username if c.isdigit()) > 5:
            score += 10
            indicators.append(f"Username too long with many digits ({len(username)} chars)")

    if following > 0:
        ratio = followers / following
        if following > 5000 and followers < 100:
            score += 30
            indicators.append(
                f"Very high following ({following:,}) but low followers ({followers:,}) — follow-spam pattern"
            )
        elif following > 2000 and ratio < 0.1:
            score += 20
            indicators.append(f"Low follower/following ratio ({ratio:.2f}) — possible bought followers or bot")
        elif ratio > 100 and followers > 100000:
            positive_signals.append(f"High follower/following ratio ({ratio:.0f}x) — credible account")

    if not bio or len(bio.strip()) == 0:
        score += 10
        indicators.append("Empty bio — account lacks personal info")
    elif len(bio) < 10:
        score += 5
        indicators.append(f"Very short bio ('{bio}')")
    else:
        positive_signals.append("Has complete bio")

    if verified:
        score -= 20
        positive_signals.append("Verified account (verified badge)")

    if post_count == 0 and followers > 1000:
        score += 25
        indicators.append(f"No posts but {followers:,} followers — possible bought followers")
    elif post_count > 0 and followers > 0:
        posts_per_follower = followers / post_count
        if posts_per_follower > 10000:
            score += 15
            indicators.append(
                f"Unusual follower/post ratio ({posts_per_follower:.0f}/post) — possible fake followers"
            )

    profile_pic = (
        profile.get("profile_picture") or profile.get("avatar") or
        profile.get("profile_image_url") or profile.get("thumbnail") or ""
    )
    if not profile_pic:
        score += 10
        indicators.append("No profile picture")

    if created_at:
        try:
            if isinstance(created_at, str):
                for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d", "%a %b %d %H:%M:%S %z %Y"):
                    try:
                        dt = datetime.strptime(created_at[:25], fmt)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        age_days = (datetime.now(timezone.utc) - dt).days
                        if age_days < 30:
                            score += 20
                            indicators.append(f"New account (only {age_days} days old)")
                        elif age_days < 180:
                            score += 5
                            indicators.append(f"Account under 6 months old ({age_days} days)")
                        elif age_days > 730:
                            positive_signals.append(f"Long-standing account ({age_days // 365} years old)")
                        break
                    except ValueError:
                        continue
        except Exception:
            pass

    score = max(0, min(100, score))

    if score >= 60:
        risk_level, color = "SUSPICIOUS", "bold red"
    elif score >= 40:
        risk_level, color = "HIGH", "red"
    elif score >= 20:
        risk_level, color = "MEDIUM", "yellow"
    elif score > 0:
        risk_level, color = "LOW", "cyan"
    else:
        risk_level, color = "CLEAN", "green"

    return {
        "platform": platform,
        "suspicion_score": score,
        "risk_level": risk_level,
        "color": color,
        "indicators": indicators,
        "positive_signals": positive_signals,
    }


def print_account_analysis(analysis: dict):
    """Display bot/fake account analysis results."""
    score = analysis.get("suspicion_score", 0)
    risk = analysis.get("risk_level", "UNKNOWN")
    color = analysis.get("color", "white")
    platform = analysis.get("platform", "")

    label = f"[{platform}] " if platform and platform != "unknown" else ""
    console.print(f"\n  [bold]🔍 {label}Bot/Fake Account Analysis:[/bold]")
    console.print(f"  Suspicion Score: [{color}]{score}/100 — {risk}[/{color}]")

    indicators = analysis.get("indicators", [])
    positives = analysis.get("positive_signals", [])

    if indicators:
        console.print("  [bold yellow]Suspicious indicators:[/bold yellow]")
        for ind in indicators:
            console.print(f"    [yellow]⚠ {ind}[/yellow]")

    if positives:
        console.print("  [bold green]Positive signals:[/bold green]")
        for pos in positives:
            console.print(f"    [green]✓ {pos}[/green]")

    if not indicators and not positives:
        console.print("  [dim]Insufficient data for analysis[/dim]")
