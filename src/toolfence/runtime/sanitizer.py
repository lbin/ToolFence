from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


DEFAULT_PATTERNS = {
    "aws_access_key": {
        "pattern": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "replacement": "[AWS_ACCESS_KEY_REDACTED]",
    },
    "gcp_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "replacement": "[GCP_API_KEY_REDACTED]",
    },
    "github_token": {
        "pattern": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}",
        "replacement": "[GITHUB_TOKEN_REDACTED]",
    },
    "github_pat": {
        "pattern": r"github_pat_[A-Za-z0-9_]{20,}",
        "replacement": "[GITHUB_PAT_REDACTED]",
    },
    "gitlab_token": {
        "pattern": r"glpat-[A-Za-z0-9\-_]{20,}",
        "replacement": "[GITLAB_TOKEN_REDACTED]",
    },
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
        "replacement": "[JWT_TOKEN_REDACTED]",
    },
    "bearer_token": {
        "pattern": r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
        "replacement": "[BEARER_TOKEN_REDACTED]",
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9A-Za-z-]{20,}",
        "replacement": "[SLACK_TOKEN_REDACTED]",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
        "replacement": "[SLACK_WEBHOOK_REDACTED]",
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_-]+",
        "replacement": "[DISCORD_WEBHOOK_REDACTED]",
    },
    "telegram_bot_token": {
        "pattern": r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b",
        "replacement": "[TELEGRAM_BOT_TOKEN_REDACTED]",
    },
    "stripe_key": {
        "pattern": r"(?i)(sk|rk)_live_[0-9a-zA-Z]{24,}",
        "replacement": "[STRIPE_KEY_REDACTED]",
    },
    "sendgrid_token": {
        "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "replacement": "[SENDGRID_TOKEN_REDACTED]",
    },
    "db_connection_string": {
        "pattern": r"(?i)(mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+",
        "replacement": "[DB_CONNECTION_REDACTED]",
    },
    "ssh_private_key": {
        "pattern": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{1,8192}?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "replacement": "[SSH_PRIVATE_KEY_REDACTED]",
    },
    "pgp_private_key": {
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{1,8192}?-----END PGP PRIVATE KEY BLOCK-----",
        "replacement": "[PGP_PRIVATE_KEY_REDACTED]",
    },
    "generic_password": {
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "replacement": "[PASSWORD_REDACTED]",
    },
    "generic_secret": {
        "pattern": r"(?i)(secret|token|api[_-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9\-_./+=]{16,}['\"]?",
        "replacement": "[SECRET_REDACTED]",
    },
}


@dataclass(slots=True)
class SanitizerMatch:
    name: str
    start: int
    end: int
    sample: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "start": self.start,
            "end": self.end,
            "sample": self.sample,
        }


@dataclass(slots=True)
class SanitizerPattern:
    name: str
    pattern: str
    replacement: str
    compiled: re.Pattern[str]


class Sanitizer:
    def __init__(self, patterns: dict[str, dict[str, str]] | None = None, enabled: bool = True):
        self.enabled = enabled
        source = patterns or DEFAULT_PATTERNS
        self.patterns = [
            SanitizerPattern(
                name=name,
                pattern=config["pattern"],
                replacement=config.get("replacement", f"[{name.upper()}_REDACTED]"),
                compiled=re.compile(config["pattern"]),
            )
            for name, config in source.items()
        ]

    @classmethod
    def from_policy(cls, policy: dict[str, Any]) -> "Sanitizer":
        rules = policy.get("sanitizer_rules", {})
        enabled = bool(rules.get("enabled", True))
        patterns = rules.get("patterns")
        if not isinstance(patterns, dict):
            patterns = None
        return cls(patterns=patterns, enabled=enabled)

    def sanitize(self, text: str | None) -> str:
        if text is None or not self.enabled:
            return text or ""
        result = text
        for pattern in self.patterns:
            result = pattern.compiled.sub(pattern.replacement, result)
        return result

    def detect(self, text: str | None) -> list[SanitizerMatch]:
        if text is None or not self.enabled:
            return []
        matches = []
        for pattern in self.patterns:
            for match in pattern.compiled.finditer(text):
                value = match.group(0)
                sample = value[:8] + "..." if len(value) > 11 else value
                matches.append(SanitizerMatch(pattern.name, match.start(), match.end(), sample))
        return sorted(matches, key=lambda item: (item.start, item.name))

    def sanitize_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.sanitize(value)
        if isinstance(value, list):
            return [self.sanitize_value(item) for item in value]
        if isinstance(value, dict):
            return {key: self.sanitize_value(item) for key, item in value.items()}
        return value

