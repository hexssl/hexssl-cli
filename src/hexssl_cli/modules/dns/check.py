from dataclasses import dataclass
from typing import Dict, List, Optional

import requests


DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_HEADERS = {
    "accept": "application/dns-json",
    "user-agent": "HEXSSL-CLI/0.1.0 (+https://www.hexssl.com)",
}


@dataclass
class DNSDetails:
    a_records: List[str]
    aaaa_records: List[str]
    cname: Optional[str]
    caa_records: List[str]
    www_a_records: List[str]
    www_aaaa_records: List[str]
    www_cname: Optional[str]
    apex_www_consistent: bool
    consistency_note: str


def inspect_dns(domain: str, timeout: float = 5.0) -> DNSDetails:
    a_records = _lookup_records(domain, "A", timeout)
    aaaa_records = _lookup_records(domain, "AAAA", timeout)
    cname_records = _lookup_records(domain, "CNAME", timeout)
    caa_records = _lookup_records(domain, "CAA", timeout)

    www_domain = "www.{0}".format(domain)
    www_a_records = _lookup_records(www_domain, "A", timeout)
    www_aaaa_records = _lookup_records(www_domain, "AAAA", timeout)
    www_cname_records = _lookup_records(www_domain, "CNAME", timeout)

    apex_www_consistent, consistency_note = _evaluate_consistency(
        a_records=a_records,
        aaaa_records=aaaa_records,
        www_a_records=www_a_records,
        www_aaaa_records=www_aaaa_records,
        www_cname=www_cname_records[0] if www_cname_records else None,
    )

    return DNSDetails(
        a_records=a_records,
        aaaa_records=aaaa_records,
        cname=cname_records[0] if cname_records else None,
        caa_records=caa_records,
        www_a_records=www_a_records,
        www_aaaa_records=www_aaaa_records,
        www_cname=www_cname_records[0] if www_cname_records else None,
        apex_www_consistent=apex_www_consistent,
        consistency_note=consistency_note,
    )


def _lookup_records(name: str, record_type: str, timeout: float) -> List[str]:
    response = requests.get(
        DOH_URL,
        params={"name": name, "type": record_type},
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
        values.append(_normalize_record_value(data))

    return values


def _normalize_record_value(value: str) -> str:
    if value.endswith("."):
        return value[:-1]
    return value


def _evaluate_consistency(
    a_records: List[str],
    aaaa_records: List[str],
    www_a_records: List[str],
    www_aaaa_records: List[str],
    www_cname: Optional[str],
) -> tuple:
    if www_cname:
        return True, "www resolves through CNAME."

    apex_addresses = sorted(set(a_records + aaaa_records))
    www_addresses = sorted(set(www_a_records + www_aaaa_records))

    if not www_addresses:
        return False, "www has no A, AAAA, or CNAME record."

    if apex_addresses == www_addresses:
        return True, "apex and www resolve to the same addresses."

    overlap = set(apex_addresses).intersection(set(www_addresses))
    if overlap:
        return True, "apex and www partially overlap."

    return False, "apex and www resolve differently."
