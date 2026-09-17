"""Launch pricing. Quotas reset at the start of each UTC calendar month."""
import os

PLANS = {
    "free": {"name": "Free", "usd_monthly": 0, "checks_monthly": 1000, "requests_per_minute": 60},
    "pro": {"name": "Pro", "usd_monthly": 19, "checks_monthly": 10000, "requests_per_minute": 1000},
    "team": {"name": "Team", "usd_monthly": 79, "checks_monthly": 100000, "requests_per_minute": 5000},
}


def price_map():
    return {value: plan for plan in ("pro", "team")
            if (value := os.environ.get("PKGGUARD_STRIPE_PRICE_" + plan.upper(), ""))}
