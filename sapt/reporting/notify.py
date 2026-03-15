"""
SAPT Notification Module — Telegram & Slack notifications.
"""

from __future__ import annotations

from typing import Optional

import aiohttp

from sapt.core.logger import get_logger
from sapt.core.exceptions import NotificationError


async def send_telegram(
    bot_token: str,
    chat_id: str,
    message: str,
) -> bool:
    """Send a Telegram notification."""
    logger = get_logger()

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    logger.debug("Telegram notification sent")
                    return True
                else:
                    error = await resp.text()
                    logger.warning(f"Telegram notification failed: {error}")
                    return False
    except Exception as e:
        logger.warning(f"Telegram notification error: {e}")
        return False


async def send_slack(
    webhook_url: str,
    message: str,
) -> bool:
    """Send a Slack notification via webhook."""
    logger = get_logger()

    payload = {"text": message}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    logger.debug("Slack notification sent")
                    return True
                else:
                    logger.warning(f"Slack notification failed: {resp.status}")
                    return False
    except Exception as e:
        logger.warning(f"Slack notification error: {e}")
        return False


async def notify(config: dict, message: str, event_type: str = "info"):
    """Send notification based on config settings."""
    # Telegram
    tg_config = config.get("notify", {}).get("telegram", {})
    if tg_config.get("enabled", False):
        notify_on = tg_config.get("notify_on", [])
        if event_type in notify_on or "all" in notify_on:
            await send_telegram(
                tg_config["bot_token"],
                tg_config["chat_id"],
                message,
            )

    # Slack
    slack_config = config.get("notify", {}).get("slack", {})
    if slack_config.get("enabled", False):
        webhook = slack_config.get("webhook_url", "")
        if webhook:
            await send_slack(webhook, message)
