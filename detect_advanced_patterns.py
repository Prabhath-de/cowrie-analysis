"""
detect_advanced_patterns.py

Additive detection functions for two attack patterns confirmed present in
the node01 dataset but currently invisible to both scoring pipelines:

  1. SSH persistence/backdoor injection (chattr .ssh tampering +
     authorized_keys key injection) -- 15+14 hits in your raw command
     frequency dump, zero signal in threat_score_v2's dropper_pattern or
     post_auth_severity_v3's category classifier.

  2. Chained one-liner droppers (fetch + chmod/execute, or fetch piped
     straight to a shell, all inside a single compound command string) --
     confirmed present (the scp+wget/curl fallback payload) but invisible
     to get_category() in post_auth_severity_v3.py / post_auth_combined_v3.py
     because that function only inspects the FIRST TOKEN of a command.

Pure functions over a single raw command string, no dependency on
anything else in the repo. Drop this file into cowrie-analysis/ and
import from it -- nothing else needs to move.
"""

import re

_SSH_BACKDOOR_RES = {
    "authorized_keys": re.compile(r"authorized_keys", re.IGNORECASE),
    "pubkey": re.compile(r"\b(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2)\b", re.IGNORECASE),
    "chattr_ssh": re.compile(r"\bchattr\b.*\.ssh|\.ssh.*\bchattr\b", re.IGNORECASE),
}

_DROPPER_RES = {
    "fetch": re.compile(r"\b(wget|curl|tftp|scp|ftp)\b", re.IGNORECASE),
    "chmod_exec": re.compile(r"\bchmod\s+(\+x|[0-7]*7[0-7]{2})\b", re.IGNORECASE),
    "execute": re.compile(r"(^|[;&|]\s*)(\./\S+|(sh|bash|ash|dash)\s+\S+)", re.IGNORECASE),
    "pipe_exec": re.compile(r"\b(wget|curl)\b[^\n;]*\|\s*(sh|bash|ash)\b", re.IGNORECASE),
}


def has_ssh_backdoor_pattern(command: str) -> bool:
    """True if this (possibly chained) command writes an attacker key into
    authorized_keys, or tampers with .ssh's immutable attribute via chattr.
    Confirmed pattern in your node01 data:
        chattr -ia .ssh; ... echo "ssh-rsa ..." >> authorized_keys
    """
    if not command:
        return False
    has_keys = bool(_SSH_BACKDOOR_RES["authorized_keys"].search(command))
    has_pubkey = bool(_SSH_BACKDOOR_RES["pubkey"].search(command))
    has_chattr = bool(_SSH_BACKDOOR_RES["chattr_ssh"].search(command))
    return (has_keys and has_pubkey) or has_chattr


def has_dropper_oneliner_pattern(command: str) -> bool:
    """True if this (possibly chained) command fetches a remote file and
    either pipes it straight into a shell, or chmods/executes it later in
    the same line. Confirmed pattern in your node01 data: the scp with
    wget/curl-fallback payload, entirely inside one command.input event.
    """
    if not command:
        return False
    has_fetch = bool(_DROPPER_RES["fetch"].search(command))
    has_chmod = bool(_DROPPER_RES["chmod_exec"].search(command))
    has_exec = bool(_DROPPER_RES["execute"].search(command))
    has_pipe = bool(_DROPPER_RES["pipe_exec"].search(command))
    return has_pipe or (has_fetch and (has_chmod or has_exec))


def has_staged_dropper_pattern(commands) -> bool:
    """True if, across ALL commands in the given list (order not required),
    a fetch appears in some command and a chmod +x or explicit execution
    appears in some -- possibly different -- command.

    Complements has_dropper_oneliner_pattern(), which only catches the
    pattern when fetch+chmod/exec are inside ONE command string. Use this
    when you don't have session boundaries to scope the check tighter
    (e.g. a flat per-event CSV with no session column) -- it's IP-level
    rather than session-level, so slightly coarser, but still requires
    both a fetch AND a follow-through step to fire, not just a bare wget.
    """
    texts = [c or "" for c in commands]
    if not texts:
        return False
    has_fetch = any(_DROPPER_RES["fetch"].search(t) for t in texts)
    has_chmod = any(_DROPPER_RES["chmod_exec"].search(t) for t in texts)
    has_exec = any(_DROPPER_RES["execute"].search(t) for t in texts)
    return has_fetch and (has_chmod or has_exec)


def has_staged_ssh_backdoor_pattern(commands) -> bool:
    """Aggregate version of has_ssh_backdoor_pattern() across multiple
    commands, for the same reason as has_staged_dropper_pattern() above --
    in case a future session splits the chattr step and the authorized_keys
    write across separate command.input events instead of one line.
    """
    texts = [c or "" for c in commands]
    if not texts:
        return False
    has_keys = any(_SSH_BACKDOOR_RES["authorized_keys"].search(t) for t in texts)
    has_pubkey = any(_SSH_BACKDOOR_RES["pubkey"].search(t) for t in texts)
    has_chattr = any(_SSH_BACKDOOR_RES["chattr_ssh"].search(t) for t in texts)
    return (has_keys and has_pubkey) or has_chattr
