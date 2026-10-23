from django.test import TestCase
from django.urls import reverse


class SpoofCheckTests(TestCase):
    def test_spoof_check_page_loads(self):
        response = self.client.get(reverse("spoof_check"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "spoof_check.html")

    def test_invalid_domain_is_rejected_before_dns_lookup(self):
        response = self.client.post(reverse("spoof_check"), {"host": "not a domain"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Enter a valid domain name")
