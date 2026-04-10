from dataclasses import dataclass
from typing import List, Optional

import requests


DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_HEADERS = {
    "accept": "application/dns-json",
    "user-agent": "HEXSSL-CLI/0.1.0 (+https://www.hexssl.com)",
}


@dataclass
class MailDetails:
    selector: str
    spf_records: List[str]
    spf_valid: bool
    spf_issue: Optional[str]
    dmarc_record: Optional[str]
    dmarc_valid: bool
    dmarc_policy: Optional[str]
    dmarc_issue: Optional[str]
    dkim_record: Optional[str]
    dkim_valid: bool
    dkim_issue: Optional[str]


def inspect_mail(domain: str, selector: str, timeout: float = 5.0) -> MailDetails:
    root_txt_records = _lookup_txt_records(domain, timeout)
    dmarc_txt_records = _lookup_txt_records("_dmarc.{0}".format(domain), timeout)
    dkim_txt_records = _lookup_txt_records(
        "{0}._domainkey.{1}".format(selector, domain),
        timeout,
    )

    spf_records = [record for record in root_txt_records if record.lower().startswith("v=spf1")]
    spf_valid, spf_issue = _evaluate_spf(spf_records)

    dmarc_record = _first_prefixed_record(dmarc_txt_records, "v=dmarc1")
    dmarc_valid, dmarc_policy, dmarc_issue = _evaluate_dmarc(dmarc_record)

    dkim_record = _first_dkim_record(dkim_txt_records)
    dkim_valid, dkim_issue = _evaluate_dkim(dkim_record)

    return MailDetails(
        selector=selector,
        spf_records=spf_records,
        spf_valid=spf_valid,
        spf_issue=spf_issue,
        dmarc_record=dmarc_record,
        dmarc_valid=dmarc_valid,
        dmarc_policy=dmarc_policy,
        dmarc_issue=dmarc_issue,
        dkim_record=dkim_record,
        dkim_valid=dkim_valid,
        dkim_issue=dkim_issue,
    )


def _lookup_txt_records(name: str, timeout: float) -> List[str]:
    response = requests.get(
        DOH_URL,
        params={"name": name, "type": "TXT"},
        headers=DOH_HEADERS,
        timeout=timeout,
    )
    response.raise_for_status()

    payload = response.json()
    answers = payload.get("Answer", [])
    values = []

    for answer in answers:
        data = answer.get("data")
        if not data:
            continue
        values.append(_normalize_txt_value(data))

    return values


def _normalize_txt_value(value: str) -> str:
    normalized = value.replace('" "', "")
    if normalized.startswith('"') and normalized.endswith('"') and len(normalized) >= 2:
        normalized = normalized[1:-1]
    return normalized


def _first_prefixed_record(records: List[str], prefix: str) -> Optional[str]:
    prefix_lower = prefix.lower()
    for record in records:
        if record.lower().startswith(prefix_lower):
            return record
    return None


def _first_dkim_record(records: List[str]) -> Optional[str]:
    for record in records:
        lowered = record.lower()
        if "v=dkim1" in lowered or "p=" in lowered:
            return record
    return None


def _evaluate_spf(records: List[str]) -> tuple:
    if not records:
        return False, "missing"
    if len(records) > 1:
        return False, "multiple"

    record = records[0].strip()
    if not record.lower().startswith("v=spf1 "):
        return False, "malformed"

    tokens = record.split()
    if len(tokens) < 2:
        return False, "malformed"

    return True, None


def _evaluate_dmarc(record: Optional[str]) -> tuple:
    if not record:
        return False, None, "missing"

    tags = _parse_tag_pairs(record)
    policy = tags.get("p")
    if not policy:
        return False, None, "malformed"

    if policy == "none":
        return True, policy, "weak_policy"

    return True, policy, None


def _evaluate_dkim(record: Optional[str]) -> tuple:
    if not record:
        return False, "missing"

    lowered = record.lower()
    if "v=dkim1" not in lowered or "p=" not in lowered:
        return False, "malformed"

    tags = _parse_tag_pairs(record)
    public_key = tags.get("p", "")
    if not public_key.strip():
        return False, "malformed"

    return True, None


def _parse_tag_pairs(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        token = part.strip()
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags
