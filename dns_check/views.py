import re
import dns.resolver
from django.shortcuts import render

DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def fetch_dns_info(domain):
    record_types = ["A", "AAAA", "MX", "NS", "CNAME", "SOA", "TXT", "PTR"]
    dns_info = {}
    for record_type in record_types:
        try:
            answer = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False, lifetime=4)
            if answer:
                dns_info[record_type] = [str(rdata) for rdata in answer]
            else:
                dns_info[record_type] = []
        except dns.resolver.NXDOMAIN:
            dns_info[record_type] = ["Domain does not exist"]
            break
        except dns.resolver.NoNameservers:
            dns_info[record_type] = ["No DNS nameservers responded"]
        except dns.resolver.LifetimeTimeout:
            dns_info[record_type] = ["DNS query timed out"]
        except Exception as exc:
            dns_info[record_type] = [str(exc)]
    return dns_info


def dns_check(request):
    records = {}
    domain = ""
    error = ""
    if request.method == "POST":
        domain = request.POST.get("domain", "").strip().rstrip(".")
        if not DOMAIN_PATTERN.fullmatch(domain):
            error = "Enter a valid domain name, for example google.com."
        else:
            records = fetch_dns_info(domain)
    return render(request, "dns_records.html", {"records": records, "domain": domain, "error": error})
