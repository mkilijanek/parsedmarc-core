# -*- coding: utf-8 -*-

"""DMARC Policy Record parsing and DNS policy discovery (RFC 9989).

:func:`parse_dmarc_record` parses one DMARC Policy Record (RFC 9989 §4.7,
§4.8). :func:`discover_dmarc_policy` finds the record that applies to a
domain with the DNS Tree Walk (§4.10), determines the Organizational Domain
(§4.10.2), and resolves the policy that applies to the domain (§4.10.1).

Every DNS query goes through :func:`parsedmarc.utils.query_dns`, so the
configured nameservers, timeout, and retries apply.
"""

from __future__ import annotations

import re

import dns.exception
import dns.name
import dns.resolver

from parsedmarc.constants import DEFAULT_DNS_MAX_RETRIES, DEFAULT_DNS_TIMEOUT
from parsedmarc.log import logger
from parsedmarc.types import DMARCPolicyDiscovery, DMARCPolicyRecord
from parsedmarc.utils import query_dns

# RFC 9989 §4.10: "Author Domains with more than eight labels do not result
# in more than eight DNS queries."
MAX_TREE_WALK_QUERIES = 8

_POLICY_VALUES = frozenset({"none", "quarantine", "reject"})
_ALIGNMENT_VALUES = frozenset({"r", "s"})
_PSD_VALUES = frozenset({"y", "n", "u"})
_YORN_VALUES = frozenset({"y", "n"})
_FO_VALUES = frozenset({"0", "1", "d", "s"})

# §4.8: dmarc-version = "v" equals %s"DMARC1", with
# equals = *WSP "=" *WSP. Used for the §4.10 step 2 filter, which discards
# records "that do not start with a "v" tag that identifies the current
# version of DMARC" before counting how many remain.
_VERSION_RE = re.compile(r"^[ \t]*v[ \t]*=[ \t]*DMARC1[ \t]*(?:;|$)")
# §4.8: dmarc-tag = 1*ALPHA equals 1*dmarc-value
_TAG_NAME_RE = re.compile(r"^[A-Za-z]+$")
# §4.8: obs-dmarc-uri = dmarc-uri obs-dmarc-report-size, where
# obs-dmarc-report-size = "!" 1*DIGIT [ "k" / "m" / "g" / "t" ]. The size
# suffix is obsolete and dropped; the URI before it is kept.
_OBS_REPORT_SIZE_RE = re.compile(r"![0-9]+[kmgtKMGT]?$")
# A syntactic check for dmarc-uri (§4.8: dmarc-uri = URI, the RFC 3986
# rule): a scheme, a colon, and a non-empty remainder. §4.8 also requires
# commas and exclamation points inside a URI to be percent-encoded, so a
# literal "!" or "," means the URI is malformed. This is a deliberately
# shallow check rather than a full RFC 3986 parser.
_URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s!,]+$")


def to_a_label(domain: str) -> str:
    """Return *domain* in lowercase A-label (ASCII) form, without a
    trailing dot, for use as a DNS query name.

    Internationalized labels are converted with dnspython's default IDNA
    codec. This is used only to build query names and to count labels; it
    is never applied to values stored in parsed reports.

    Raises:
        ValueError: *domain* is empty or is not a valid DNS name.
    """
    domain = domain.strip().rstrip(".")
    if not domain:
        raise ValueError("Empty domain name")
    try:
        name = dns.name.from_text(domain)
    except (dns.exception.DNSException, UnicodeError) as e:
        raise ValueError(f"Invalid domain name {domain!r}: {e}") from e
    return name.to_text(omit_final_dot=True).lower()


def _parse_tags(record: str) -> dict[str, str] | None:
    """Split a DMARC Policy Record into its tags.

    Returns ``None`` when the record is not a DMARC Policy Record: the first
    tag is not ``v=DMARC1`` (§4.7: "the entire record MUST be ignored"), or
    a tag name occurs more than once. RFC 9989 does not address duplicate
    tags itself; §4.7 says DMARC Policy Records "follow the extensible
    "tag-value" syntax for DNS-based key records defined in DKIM", and
    RFC 6376 §3.2 says that if a tag name occurs more than once "the entire
    tag-list is invalid".

    Tag names are case-sensitive (RFC 6376 §3.2: "Tags MUST be interpreted
    in a case-sensitive manner"), so ``P=reject`` is an unknown tag, not
    ``p``. Segments that are not ``name=value`` with a 1*ALPHA name and a
    non-empty value are syntax errors and are skipped (§4.8: syntax errors
    are "discarded in favor of default values (if any) or ignored
    outright").
    """
    if not _VERSION_RE.match(record):
        return None
    tags: dict[str, str] = {}
    for segment in record.split(";"):
        if "=" not in segment:
            continue
        name, value = segment.split("=", 1)
        name = name.strip(" \t")
        value = value.strip(" \t")
        if not _TAG_NAME_RE.match(name) or not value:
            continue
        if name in tags:
            return None
        tags[name] = value
    return tags


def _parse_uri_list(value: str) -> list[str]:
    """Return the syntactically valid URIs of a dmarc-urilist (§4.8),
    dropping any obsolete ``!size`` suffix and skipping malformed URIs."""
    uris = []
    for item in value.split(","):
        uri = _OBS_REPORT_SIZE_RE.sub("", item.strip(" \t"))
        if _URI_RE.match(uri):
            uris.append(uri)
    return uris


def _enum(value: str | None, allowed: frozenset[str]) -> str | None:
    """Return *value* lowercased if it is one of *allowed*, else ``None``.

    The enumerated values in the §4.8 ABNF are quoted strings, which
    RFC 5234 §2.3 defines as case-insensitive (unlike the explicitly
    case-sensitive %s"DMARC1")."""
    if value is None:
        return None
    value = value.lower()
    return value if value in allowed else None


def _parse_fo(value: str | None) -> str:
    """Return a valid ``fo`` value, or the §4.7 default ``"0"``.

    §4.8 dmarc-fo is colon-separated ``0``, ``1``, ``d``, and ``s`` options,
    each at most once, in which ``0`` and ``1`` are mutually exclusive.
    """
    if value is None:
        return "0"
    options = [option.strip(" \t").lower() for option in value.split(":")]
    if (
        len(set(options)) != len(options)
        or not set(options) <= _FO_VALUES
        or {"0", "1"} <= set(options)
    ):
        return "0"
    return ":".join(options)


def effective_subdomain_policies(record: DMARCPolicyRecord) -> tuple[str, str]:
    """Return the ``(sp, np)`` that apply, with the RFC 9989 §4.7 fallbacks
    ``np`` -> ``sp`` -> ``p`` resolved for a record that leaves them unset."""
    subdomain_policy = record["sp"] or record["p"]
    return subdomain_policy, record["np"] or subdomain_policy


def _record_from_tags(raw: str, tags: dict[str, str]) -> DMARCPolicyRecord | None:
    """Build a :class:`~parsedmarc.types.DMARCPolicyRecord` from split tags,
    applying the RFC 9989 §4.7 defaults and the §4.10.1 rules for invalid
    policy tags. See :func:`parse_dmarc_record`."""
    rua = _parse_uri_list(tags["rua"]) if "rua" in tags else []
    ruf = _parse_uri_list(tags["ruf"]) if "ruf" in tags else []

    p = _enum(tags.get("p"), _POLICY_VALUES)
    sp = _enum(tags.get("sp"), _POLICY_VALUES)
    np = _enum(tags.get("np"), _POLICY_VALUES)
    p_invalid = "p" in tags and p is None
    sp_invalid = "sp" in tags and sp is None
    np_invalid = "np" in tags and np is None
    if p_invalid or sp_invalid or np_invalid:
        # §4.10.1: a record without a valid "p" tag, or with an invalid "sp"
        # or "np" tag, is handled "as if a record containing "p=none" was
        # retrieved" when "rua" holds at least one syntactically valid URI;
        # otherwise no DMARC processing applies. The RFC does not say
        # whether the record's other tags survive; they are kept (rua in
        # particular is what makes the record usable at all).
        if not rua:
            return None
        p, sp, np = "none", None, None
    elif p is None:
        # §4.7: if "p" "is not present in an otherwise syntactically valid
        # DMARC Policy Record, then the record is treated as if it included
        # "p=none"". §4.10.1 also covers a record that "does not contain a
        # valid "p" tag", which would make an absent "p" without "rua"
        # unusable; this follows §4.7, the more specific text for absence,
        # and applies the §4.10.1 rule to a "p" that is present but invalid.
        p = "none"

    return {
        "raw": raw,
        "p": p,
        "sp": sp,
        "np": np,
        "adkim": _enum(tags.get("adkim"), _ALIGNMENT_VALUES) or "r",
        "aspf": _enum(tags.get("aspf"), _ALIGNMENT_VALUES) or "r",
        "fo": _parse_fo(tags.get("fo")),
        "psd": _enum(tags.get("psd"), _PSD_VALUES) or "u",
        "t": _enum(tags.get("t"), _YORN_VALUES) or "n",
        "rua": rua,
        "ruf": ruf,
    }


def parse_dmarc_record(record: str) -> DMARCPolicyRecord | None:
    """Parse a DMARC Policy Record (the text of a ``_dmarc`` TXT record).

    Follows RFC 9989 §4.7 and §4.8:

    - ``v=DMARC1`` must be the first tag, with ``DMARC1`` case-sensitive;
      otherwise the record is ignored and ``None`` is returned.
    - Unknown tags are ignored ("unknown tags MUST be ignored"), and so are
      the historic ``pct``, ``rf``, and ``ri`` tags, which are not parsed
      or defaulted.
    - An absent ``p`` is treated as ``p=none``.
    - A ``p`` that is present but not ``none``/``quarantine``/``reject``,
      or an invalid ``sp`` or ``np``, makes the record act as ``p=none``
      (with ``sp`` and ``np`` cleared) if ``rua`` holds at least one
      syntactically valid URI; without one, the record is unusable and
      ``None`` is returned (§4.10.1).
    - A malformed ``adkim``, ``aspf``, ``fo``, ``psd``, or ``t`` value falls
      back to its default (``r``, ``r``, ``0``, ``u``, ``n``).
    - A record that repeats a tag name is invalid and ``None`` is returned
      (RFC 6376 §3.2, whose tag-value syntax §4.7 adopts).

    Args:
        record (str): The record text, with any multi-string TXT chunks
            already concatenated

    Returns:
        DMARCPolicyRecord | None: The parsed record, or ``None`` if *record*
        is not a usable DMARC Policy Record
    """
    tags = _parse_tags(record)
    if tags is None:
        return None
    return _record_from_tags(record.strip(), tags)


def _query_dmarc_record(
    name: str,
    *,
    nameservers: list[str] | None,
    timeout: float,
    retries: int,
) -> tuple[str, dict[str, str]] | None:
    """Query ``_dmarc.<name>`` and apply the §4.10 step 2 filter.

    Records that do not start with ``v=DMARC1`` are discarded; if more than
    one remains, "they are all discarded". Returns the single remaining
    record's text and tags, or ``None``. NXDOMAIN and an empty answer mean
    no record; any other DNS error propagates.
    """
    try:
        answers = query_dns(
            f"_dmarc.{name}",
            "TXT",
            nameservers=nameservers,
            timeout=timeout,
            retries=retries,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    candidates = [answer for answer in answers if _VERSION_RE.match(answer)]
    if len(candidates) != 1:
        if len(candidates) > 1:
            logger.debug(
                f"Discarding {len(candidates)} DMARC records found at "
                f"_dmarc.{name} (RFC 9989 §4.10 step 2)"
            )
        return None
    tags = _parse_tags(candidates[0])
    if tags is None:
        return None
    return candidates[0].strip(), tags


def _tree_walk(
    domain: str,
    *,
    nameservers: list[str] | None,
    timeout: float,
    retries: int,
) -> list[tuple[str, str, dict[str, str]]]:
    """Run the RFC 9989 §4.10 DNS Tree Walk starting at *domain*.

    Returns ``(domain, record text, tags)`` for every DMARC Policy Record
    found, longest domain first. The walk stops after a record with
    ``psd=n`` or ``psd=y`` (steps 2 and 6) or when no labels remain (step
    7). After the first query, a name with eight or more labels is
    shortened to seven (step 4), so at most eight queries are made.
    """
    found: list[tuple[str, str, dict[str, str]]] = []
    labels = domain.split(".")
    first_query = True
    while labels:
        name = ".".join(labels)
        result = _query_dmarc_record(
            name, nameservers=nameservers, timeout=timeout, retries=retries
        )
        if result is not None:
            raw, tags = result
            found.append((name, raw, tags))
            if _enum(tags.get("psd"), _YORN_VALUES) is not None:
                break
        if first_query and len(labels) >= MAX_TREE_WALK_QUERIES:
            labels = labels[-(MAX_TREE_WALK_QUERIES - 1) :]
        else:
            labels = labels[1:]
        first_query = False
    return found


def _organizational_domain(
    domain: str, found: list[tuple[str, str, dict[str, str]]]
) -> str:
    """Select the Organizational Domain per RFC 9989 §4.10.2.

    The records are considered from the longest domain to the shortest: a
    record with ``psd=n`` makes its own domain the Organizational Domain;
    a record with ``psd=y``, other than one at *domain* (where the walk
    started), makes the domain one label below it the Organizational
    Domain; otherwise the record at the name with the fewest labels wins.
    With no records at all, *domain* itself is the Organizational Domain.
    """
    labels = domain.split(".")
    for name, _raw, tags in found:
        psd = _enum(tags.get("psd"), _YORN_VALUES)
        if psd == "n":
            return name
        if psd == "y" and name != domain:
            return ".".join(labels[-(name.count(".") + 2) :])
    if found:
        return found[-1][0]
    return domain


def _domain_exists(
    domain: str,
    *,
    nameservers: list[str] | None,
    timeout: float,
    retries: int,
) -> bool:
    """Return whether *domain* exists, for choosing between ``sp`` and
    ``np``.

    RFC 9989 §3.2.13 defines a non-existent domain by the NXDOMAIN response
    code (per RFC 8020, the name and every name below it do not exist). It
    does not name a query type; NXDOMAIN applies to the name regardless of
    type, so a single A query is made. An empty answer (NODATA) means the
    name exists. Any other DNS error propagates.
    """
    try:
        query_dns(
            domain, "A", nameservers=nameservers, timeout=timeout, retries=retries
        )
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True
    return True


def discover_dmarc_policy(
    domain: str,
    *,
    nameservers: list[str] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> DMARCPolicyDiscovery:
    """Discover the DMARC policy that applies to *domain* (RFC 9989 §4.10).

    A DNS Tree Walk (§4.10) starts at ``_dmarc.<domain>`` and makes at most
    eight queries. The Organizational Domain is selected from the records
    found per §4.10.2. The DMARC Policy Record that applies is, per §4.10.1
    in order of preference, the usable record at *domain* itself, the
    record at the Organizational Domain, or the record of the Public Suffix
    Domain (the ``psd=y`` record that ended the walk).

    The effective policy is the record's ``p`` when the record is at
    *domain*. For a subdomain of the record's domain it is ``sp`` (falling
    back to ``p``) if *domain* exists, or ``np`` (falling back to ``sp``,
    then ``p``) if it does not (§4.7, §4.10.1). Whether *domain* exists is
    tested with one extra query (see ``domain_exists`` below), made only
    when those two candidates differ.

    Args:
        domain (str): The domain to discover the policy for, such as an
            Author Domain or a report's ``policy_published`` domain.
            Internationalized names are queried in A-label form.
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds
        retries (int): Number of times to retry DNS queries on timeout or
            other transient errors

    Returns:
        DMARCPolicyDiscovery: A dict with these keys, every domain name in
        lowercase A-label form:

        - ``domain``: *domain*, normalized
        - ``record``: the DMARC Policy Record that applies, or ``None`` when
          no usable record was found (§4.10.1: DMARC then does not apply)
        - ``record_domain``: the domain the record was found at, or ``None``
        - ``organizational_domain``: the Organizational Domain (§4.10.2);
          *domain* itself when no record was found
        - ``effective_policy``: ``none``, ``quarantine``, or ``reject`` for
          *domain*; ``None`` when ``record`` is ``None``
        - ``domain_exists``: ``True`` or ``False`` when the existence test
          was made, ``None`` when the policy did not depend on it

    Raises:
        ValueError: *domain* is not a valid domain name.
        dns.exception.DNSException: A DNS query failed with an error other
            than NXDOMAIN or an empty answer. RFC 9989 §4.10.1 leaves the
            handling of DNS errors to the receiver; treating a failed query
            as "no record" could select the wrong Organizational Domain, so
            discovery stops instead.
        OSError: A network error persisted through every retry.
    """
    domain = to_a_label(domain)
    found = _tree_walk(
        domain, nameservers=nameservers, timeout=timeout, retries=retries
    )
    org_domain = _organizational_domain(domain, found)
    records = {name: (raw, tags) for name, raw, tags in found}

    result: DMARCPolicyDiscovery = {
        "domain": domain,
        "record": None,
        "record_domain": None,
        "organizational_domain": org_domain,
        "effective_policy": None,
        "domain_exists": None,
    }

    # §4.10.1: the record at the Author Domain applies if it is valid;
    # otherwise the Organizational Domain's record, then the PSD's. "PSD
    # policy is not used for Organizational Domains that have published a
    # DMARC Policy Record", so the PSD record is only a fallback for an
    # Organizational Domain without one. A record whose policy tags are
    # unusable at the Author Domain is skipped ("If a valid DMARC Policy
    # Record is found there"); one selected at the Organizational Domain or
    # PSD means no DMARC processing (§4.10.1), and it is not skipped over.
    record: DMARCPolicyRecord | None = None
    record_domain: str | None = None
    if domain in records:
        record = _record_from_tags(*records[domain])
        record_domain = domain
    if record is None:
        record_domain = None
        if org_domain in records:
            record_domain = org_domain
        elif found and _enum(found[-1][2].get("psd"), _YORN_VALUES) == "y":
            record_domain = found[-1][0]
        if record_domain is not None and record_domain != domain:
            record = _record_from_tags(*records[record_domain])
    if record is None:
        return result

    result["record"] = record
    result["record_domain"] = record_domain
    if record_domain == domain:
        result["effective_policy"] = record["p"]
        return result

    subdomain_policy, nonexistent_policy = effective_subdomain_policies(record)
    if subdomain_policy == nonexistent_policy:
        result["effective_policy"] = subdomain_policy
        return result
    exists = _domain_exists(
        domain, nameservers=nameservers, timeout=timeout, retries=retries
    )
    result["domain_exists"] = exists
    result["effective_policy"] = subdomain_policy if exists else nonexistent_policy
    return result
