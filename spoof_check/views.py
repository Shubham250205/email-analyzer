import re

import dns.resolver
from django.shortcuts import render

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def _txt_value(record):
    """Convert one dnspython TXT rdata into a usable string."""
    chunks = getattr(record, "strings", None)
    if chunks is not None:
        return b"".join(chunks).decode("utf-8", errors="replace").strip()

    # Fallback for dnspython releases where TXT chunks are not exposed.
    text = record.to_text() if hasattr(record, "to_text") else str(record)
    return re.sub(r'"\s+"', "", text).strip('"')


def _fetch_txt_records(name):
    """Return TXT strings; a missing record is normal and returns an empty list."""
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=4)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []

    return [_txt_value(record) for record in answer]


def check_records(domain):
    records = {
        "domain": domain,
        "spf": False,
        "spf_details": "",
        "spf_all_present": False,
        "dmarc": False,
        "dmarc_details": "",
        "dmarc_enforced": False,
        "spoofable": True,
    }

    # SPF is published as a TXT record on the root domain.
    spf_record = next(
        (value for value in _fetch_txt_records(domain) if value.lower().startswith("v=spf1")),
        "",
    )
    if spf_record:
        records["spf"] = True
        records["spf_details"] = spf_record
        records["spf_all_present"] = bool(
            re.search(r"(?:^|\s)[~-]all(?:\s|$)", spf_record, re.IGNORECASE)
        )

    # DMARC is published on _dmarc.<domain>.
    dmarc_record = next(
        (
            value
            for value in _fetch_txt_records(f"_dmarc.{domain}")
            if value.lower().startswith("v=dmarc1")
        ),
        "",
    )
    if dmarc_record:
        records["dmarc"] = True
        records["dmarc_details"] = dmarc_record
        policy_match = re.search(
            r"(?:^|;)\s*p\s*=\s*reject\b", dmarc_record, re.IGNORECASE
        )
        records["dmarc_enforced"] = bool(policy_match)

    # This is a simplified configuration indicator, not a guarantee that a
    # particular email cannot be spoofed. SPF/DKIM alignment and receiver
    # handling also affect real-world authentication.
    if (
        records["spf"]
        and records["dmarc"]
        and records["spf_all_present"]
        and records["dmarc_enforced"]
    ):
        records["spoofable"] = False

    return records


def spoof_check(request):
    records = None
    error = ""
    if request.method == "POST":
        domain = request.POST.get("host", "").strip().rstrip(".")
        if not DOMAIN_PATTERN.fullmatch(domain):
            error = "Enter a valid domain name, for example google.com."
        else:
            try:
                records = check_records(domain)
            except dns.resolver.NoNameservers:
                error = "The domain's DNS nameservers did not respond. Please try again."
            except dns.resolver.LifetimeTimeout:
                error = "The DNS lookup timed out. Please try again."
            except Exception:
                error = "The domain could not be checked right now. Please try again."
    return render(request, "spoof_check.html", {"records": records, "error": error})
