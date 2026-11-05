"""Read operator secrets from the environment and drop them immediately."""

from __future__ import annotations

import os

ENV_NAMES = (
    "SW_SSH_HOST",
    "SW_SSH_PORT",
    "SW_SSH_USER",
    "SW_SSH_PASSWORD",
    "SW_SSH_KEY",
    "SW_SSH_JUMP",
    "SW_SSH_JUMP_PORT",
    "SW_SSH_JUMP_USER",
    "SW_SSH_JUMP_PASSWORD",
    "SW_HOST_LABEL",
)


def take_env(names: tuple[str, ...] = ENV_NAMES) -> dict[str, str | None]:
    """Pop the named variables so later code and child processes cannot see them."""
    return {name: os.environ.pop(name, None) for name in names}


def scrub(text: str, secrets: list[str | None]) -> str:
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "<redacted>")
    return redacted
