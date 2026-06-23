from __future__ import annotations

import re


class CommandNormalizer:
    def normalize(self, command: str) -> tuple[str, list[str]]:
        warnings = self.suspicious_patterns(command)
        normalized = command
        normalized = re.sub(r"''|\"\"", "", normalized)
        normalized = re.sub(r"'([^']*)'", r"\1", normalized)
        normalized = re.sub(r'"([^"]*)"', r"\1", normalized)
        normalized = re.sub(r"\\([A-Za-z0-9\s_\-./])", r"\1", normalized)
        normalized = normalized.replace("${IFS}", " ").replace("$IFS", " ")
        return normalized, warnings

    def obfuscation_level(self, command: str) -> str:
        score = 0
        if re.search(r"\$\(|`", command):
            score += 2
        if re.search(r"\\x[0-9a-fA-F]{2}|\\[0-7]{3}|\\u[0-9a-fA-F]{4}", command):
            score += 3
        if re.search(r"\${?IFS}?", command):
            score += 2
        if "''" in command or '""' in command:
            score += 1
        if re.search(r"\\[A-Za-z]", command):
            score += 1
        if re.search(r"(?i)(base64|openssl)\s+(-d|--decode|enc)", command) and ("|" in command or "`" in command):
            score += 3
        if re.search(r"(?i)\beval\b", command):
            score += 2
        if score == 0:
            return "none"
        if score <= 2:
            return "low"
        if score <= 5:
            return "medium"
        return "high"

    def suspicious_patterns(self, command: str) -> list[str]:
        patterns = []
        checks = [
            ("command_substitution", r"\$\(|`"),
            ("hex_or_octal_escape", r"\\x[0-9a-fA-F]{2}|\\[0-7]{3}|\\u[0-9a-fA-F]{4}"),
            ("ifs_abuse", r"\${?IFS}?"),
            ("empty_quote_obfuscation", r"''|\"\""),
            ("backslash_escaping", r"\\[A-Za-z]"),
            ("base64_decode_pipeline", r"(?i)(base64|openssl)\s+(-d|--decode|enc).*[|`]"),
            ("eval_usage", r"(?i)\beval\b"),
        ]
        for name, pattern in checks:
            if re.search(pattern, command):
                patterns.append(name)
        return patterns

