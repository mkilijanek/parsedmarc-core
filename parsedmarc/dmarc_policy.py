# -*- coding: utf-8 -*-

"""DMARC DNS policy parsing and discovery helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional
import re


KNOWN_TAGS = {"v", "p", "sp", "adkim", "aspf", "pct", "rua", "ruf", "fo", "rf", "ri"}
URI_TAGS = {"rua", "ruf"}
POLICY_VALUES = {"none", "quarantine", "reject"}
ALIGNMENT_VALUES = {"r", "s"}
FO_VALUES = {"0", "1", "d", "s"}
MAILTO_URI_RE = re.compile(r"^mailto:([^!]+)(?:!(\d+)([kKmMgGtT]?))?$")
MAILBOX_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\."
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


@dataclass
class DmarcPolicy:
    """Canonical DMARC policy model."""

    domain: str
    p: str
    sp: Optional[str] = None
    adkim: str = "r"
    aspf: str = "r"
    pct: int = 100
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    fo: str = "0"
    rf: Optional[str] = None
    ri: int = 86400
    mode: str = "fallback"
    source: str = "subdomain"
    raw_record: str = ""


def normalize_domain(domain: str) -> str:
    """Normalize a domain to an A-label lowercase form."""
    domain = domain.strip().strip(".").lower()
    if not domain:
        return domain
    labels = []
    for label in domain.split("."):
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            labels.append(label)
    return ".".join(labels)


def domains_equal_for_alignment(left: str, right: str) -> bool:
    """Case-insensitive domain compare with IDN normalization."""
    return normalize_domain(left) == normalize_domain(right)


def _split_tag_value_pairs(record: str) -> tuple[list[tuple[str, str]], list[str]]:
    errors: list[str] = []
    pairs: list[tuple[str, str]] = []
    for part in [p.strip() for p in record.split(";") if p.strip()]:
        if "=" not in part:
            errors.append(f"Malformed tag segment: {part}")
            continue
        tag, value = part.split("=", 1)
        tag = tag.strip().lower()
        value = value.strip()
        if not re.match(r"^[a-z][a-z0-9_-]*$", tag):
            errors.append(f"Invalid tag name: {tag}")
            continue
        pairs.append((tag, value))
    return pairs, errors


def _parse_mailto_uri_list(value: str) -> tuple[Optional[list[str]], list[str]]:
    errors: list[str] = []
    uris: list[str] = []
    for raw_uri in [p.strip() for p in value.split(",") if p.strip()]:
        match = MAILTO_URI_RE.match(raw_uri)
        if not match:
            errors.append(f"Malformed URI: {raw_uri}")
            continue
        mailbox = match.group(1).strip()
        if not MAILBOX_RE.match(mailbox):
            errors.append(f"Invalid ASCII mailbox in URI: {raw_uri}")
            continue
        if any(ord(ch) > 127 for ch in mailbox):
            errors.append(f"EAI mailbox is not allowed in URI: {raw_uri}")
            continue
        uris.append(f"mailto:{mailbox.lower()}")

    if errors:
        return None, errors
    return uris, []


def _validate_policy(tags: dict[str, str]) -> tuple[Optional[dict[str, object]], list[str]]:
    errors: list[str] = []

    v = tags.get("v", "")
    if v.upper() != "DMARC1":
        errors.append("Missing or invalid v=DMARC1")

    p = tags.get("p")
    if p is None or p.lower() not in POLICY_VALUES:
        errors.append("Missing or invalid p value")

    sp = tags.get("sp")
    if sp is not None and sp.lower() not in POLICY_VALUES:
        errors.append("Invalid sp value")

    adkim = tags.get("adkim", "r")
    if adkim.lower() not in ALIGNMENT_VALUES:
        errors.append("Invalid adkim value")

    aspf = tags.get("aspf", "r")
    if aspf.lower() not in ALIGNMENT_VALUES:
        errors.append("Invalid aspf value")

    pct_raw = tags.get("pct", "100")
    if not pct_raw.isdigit():
        errors.append("pct must be an integer")
        pct = 100
    else:
        pct = int(pct_raw)
        if pct < 0 or pct > 100:
            errors.append("pct must be in range 0..100")

    fo = tags.get("fo", "0").lower()
    for part in fo.split(":"):
        if part not in FO_VALUES:
            errors.append("Invalid fo value")
            break

    rf = tags.get("rf")
    if rf is not None and not rf.strip():
        errors.append("Invalid rf value")

    ri_raw = tags.get("ri", "86400")
    if not ri_raw.isdigit() or int(ri_raw) <= 0:
        errors.append("Invalid ri value")
        ri = 86400
    else:
        ri = int(ri_raw)

    rua: list[str] = []
    ruf: list[str] = []
    for uri_tag in URI_TAGS:
        if uri_tag in tags:
            parsed, uri_errors = _parse_mailto_uri_list(tags[uri_tag])
            if uri_errors:
                errors.extend(uri_errors)
            else:
                if uri_tag == "rua":
                    rua = parsed or []
                else:
                    ruf = parsed or []

    if errors:
        return None, errors

    return {
        "p": p.lower(),
        "sp": sp.lower() if sp is not None else None,
        "adkim": adkim.lower(),
        "aspf": aspf.lower(),
        "pct": pct,
        "rua": rua,
        "ruf": ruf,
        "fo": fo,
        "rf": rf,
        "ri": ri,
    }, []


def _parse_strict(record: str, domain: str) -> tuple[Optional[DmarcPolicy], list[str]]:
    errors: list[str] = []
    pairs, pair_errors = _split_tag_value_pairs(record)
    errors.extend(pair_errors)

    if not pairs:
        errors.append("No tag-value pairs found")
        return None, errors

    if pairs[0][0] != "v":
        errors.append("v=DMARC1 must be first tag")

    tags: dict[str, str] = {}
    for tag, value in pairs:
        if tag in tags:
            errors.append(f"Duplicate tag in strict mode: {tag}")
            continue
        if tag not in KNOWN_TAGS:
            errors.append(f"Unknown tag in strict mode: {tag}")
            continue
        tags[tag] = value

    if errors:
        return None, errors

    values, validation_errors = _validate_policy(tags)
    if validation_errors:
        return None, validation_errors

    return DmarcPolicy(domain=domain, raw_record=record, mode="strict", **values), []


def _parse_fallback(record: str, domain: str) -> tuple[Optional[DmarcPolicy], list[str]]:
    errors: list[str] = []
    pairs, pair_errors = _split_tag_value_pairs(record)
    errors.extend(pair_errors)

    tags: dict[str, str] = {}
    for tag, value in pairs:
        if tag not in KNOWN_TAGS:
            continue
        if tag in tags:
            continue
        tags[tag] = value

    values, validation_errors = _validate_policy(tags)
    if validation_errors:
        errors.extend(validation_errors)
        return None, errors

    return DmarcPolicy(domain=domain, raw_record=record, mode="fallback", **values), errors


def parse_dmarc_record(
    txt: str,
    domain: str = "",
    dmarc_strict_mode: str = "auto",
) -> tuple[Optional[DmarcPolicy], Optional[str], list[str]]:
    """
    Parse a DMARC DNS TXT record using strict/fallback behavior.

    Returns:
        (policy, mode, errors)
    """
    mode = (dmarc_strict_mode or "auto").strip().lower()
    if mode not in {"auto", "strict", "legacy"}:
        mode = "auto"

    txt = (txt or "").strip().strip('"')
    if not txt:
        return None, None, ["Empty DMARC record"]

    normalized_domain = normalize_domain(domain) if domain else ""

    if mode == "strict":
        policy, errors = _parse_strict(txt, normalized_domain)
        return policy, (policy.mode if policy else None), errors

    if mode == "legacy":
        policy, errors = _parse_fallback(txt, normalized_domain)
        return policy, (policy.mode if policy else None), errors

    strict_policy, strict_errors = _parse_strict(txt, normalized_domain)
    if strict_policy:
        return strict_policy, strict_policy.mode, []

    fallback_policy, fallback_errors = _parse_fallback(txt, normalized_domain)
    if fallback_policy:
        return fallback_policy, fallback_policy.mode, strict_errors + fallback_errors

    return None, None, strict_errors + fallback_errors


def _default_dns_resolver(name: str, record_type: str) -> list[str]:
    from parsedmarc.utils import query_dns

    return query_dns(name, record_type)


def _resolve_dmarc_txt_records(
    domain: str,
    dns_resolver: Callable[[str, str], list[str]],
) -> list[str]:
    lookup_name = f"_dmarc.{domain}"
    try:
        records = dns_resolver(lookup_name, "TXT")
    except Exception:
        return []
    return [r.strip() for r in records if isinstance(r, str) and r.strip()]


def _select_candidate_record(txt_records: list[str]) -> Optional[str]:
    for record in txt_records:
        if "v=dmarc1" in record.lower().replace(" ", ""):
            return record
    return None


def discover_dmarc_policy(
    domain: str,
    dns_resolver: Optional[Callable[[str, str], list[str]]] = None,
    psl_provider=None,
    flags: Optional[dict] = None,
) -> tuple[Optional[DmarcPolicy], list[str], Optional[str]]:
    """Discover DMARC policy in subdomain -> org -> PSD order."""
    if dns_resolver is None:
        dns_resolver = _default_dns_resolver
    if flags is None:
        flags = {}

    strict_mode = (flags.get("dmarc_strict_mode") or "auto").lower()
    enable_psd = bool(flags.get("enable_psd", False))

    normalized_domain = normalize_domain(domain)
    discovery_path: list[str] = []

    if psl_provider is None:
        from parsedmarc.utils import psl as default_psl

        psl_provider = default_psl

    org_domain = psl_provider.privatesuffix(normalized_domain) or normalized_domain
    org_domain = normalize_domain(org_domain)

    public_suffix = None
    if hasattr(psl_provider, "publicsuffix"):
        public_suffix = psl_provider.publicsuffix(normalized_domain)
        if public_suffix:
            public_suffix = normalize_domain(public_suffix)

    lookup_targets: list[tuple[str, str]] = [(normalized_domain, "subdomain")]
    if org_domain and org_domain != normalized_domain:
        lookup_targets.append((org_domain, "org"))

    allow_psd = enable_psd and strict_mode in {"auto", "strict"}
    if (
        allow_psd
        and public_suffix
        and public_suffix not in {normalized_domain, org_domain}
    ):
        lookup_targets.append((public_suffix, "psd"))

    for lookup_domain, source in lookup_targets:
        txt_records = _resolve_dmarc_txt_records(lookup_domain, dns_resolver)
        discovery_path.append(f"_dmarc.{lookup_domain}:{len(txt_records)}")
        if not txt_records:
            continue

        candidate = _select_candidate_record(txt_records)
        if candidate is None:
            continue

        policy, mode, _errors = parse_dmarc_record(
            candidate,
            domain=lookup_domain,
            dmarc_strict_mode=strict_mode,
        )
        if not policy:
            continue

        if source == "psd" and mode != "strict":
            # PSD support is intentionally not applied in fallback/legacy behavior.
            continue

        policy.source = source
        policy.mode = mode or policy.mode
        return policy, discovery_path, policy.mode

    return None, discovery_path, None
