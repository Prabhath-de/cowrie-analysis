import re

_SSH_BACKDOOR_RES = {
    "authorized_keys": re.compile(
        r"authorized_keys",
        re.IGNORECASE
    ),
    "pubkey": re.compile(
        r"\b(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2)\b",
        re.IGNORECASE
    ),
    "chattr_ssh": re.compile(
        r"\bchattr\b.*\.ssh|\.ssh.*\bchattr\b",
        re.IGNORECASE
    ),
}

_DROPPER_RES = {
    "fetch": re.compile(
        r"\b(wget|curl|tftp|scp|ftp)\b",
        re.IGNORECASE
    ),
    "chmod_exec": re.compile(
        r"\bchmod\s+(?:\+x|[0-7]*7[0-7]{2})\b",
        re.IGNORECASE
    ),
    "execute": re.compile(
        r"(^|[;&|]\s*)(?:\./\S+|(?:sh|bash|ash|dash)\s+\S+)",
        re.IGNORECASE
    ),
    "pipe_exec": re.compile(
        r"\b(?:wget|curl)\b[^\n]*\|\s*(?:sh|bash|ash|dash)\b",
        re.IGNORECASE
    ),
}


def has_ssh_backdoor_pattern(command: str) -> bool:
    if not command:
        return False

    has_keys = bool(
        _SSH_BACKDOOR_RES["authorized_keys"].search(command)
    )

    has_pubkey = bool(
        _SSH_BACKDOOR_RES["pubkey"].search(command)
    )

    has_chattr = bool(
        _SSH_BACKDOOR_RES["chattr_ssh"].search(command)
    )

    return (has_keys and has_pubkey) or has_chattr


def has_dropper_oneliner_pattern(command: str) -> bool:
    if not command:
        return False

    has_fetch = bool(
        _DROPPER_RES["fetch"].search(command)
    )

    has_chmod = bool(
        _DROPPER_RES["chmod_exec"].search(command)
    )

    has_exec = bool(
        _DROPPER_RES["execute"].search(command)
    )

    has_pipe = bool(
        _DROPPER_RES["pipe_exec"].search(command)
    )

    return has_pipe or (
        has_fetch and
        (has_chmod or has_exec)
    )
