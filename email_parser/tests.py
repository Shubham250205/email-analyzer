from unittest.mock import patch

from django.contrib import admin
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from .models import ContactMessage


class ContactMessageTests(TestCase):
    def test_contact_page_loads(self):
        response = self.client.get(reverse("contact"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "contact-us.html")

    def test_contact_message_is_saved(self):
        response = self.client.post(
            reverse("contact"),
            {"name": "Test User", "email": "test@example.com", "message": "Testing contact form"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ContactMessage.objects.count(), 1)
        self.assertContains(response, "submitted successfully")

    def test_invalid_email_is_rejected(self):
        self.client.post(
            reverse("contact"),
            {"name": "Test User", "email": "not-an-email", "message": "Testing"},
        )
        self.assertEqual(ContactMessage.objects.count(), 0)

    def test_empty_fields_are_rejected(self):
        self.client.post(reverse("contact"), {"name": "", "email": "", "message": ""})
        self.assertEqual(ContactMessage.objects.count(), 0)

    def test_contact_message_is_registered_in_admin(self):
        self.assertTrue(admin.site.is_registered(ContactMessage))


class EmailParserTests(TestCase):
    def test_parser_page_loads(self):
        response = self.client.get(reverse("index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "parser.html")

    def test_analyze_without_file_returns_parser_page(self):
        response = self.client.post(reverse("analyze"), {})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "parser.html")


class EmailAnalysisTests(TestCase):
    @patch("email_parser.email_analyzer.get_mx_records", return_value=[])
    @patch("email_parser.email_analyzer.analyze_ip_geolocation", return_value=None)
    @patch("email_parser.email_analyzer.url_scan")
    def test_analyze_valid_eml_file(self, mock_url_scan, mock_geo, mock_mx):
        from .email_analyzer import analyze_email

        eml_content = (
            b"From: sender@example.com\r\n"
            b"To: receiver@example.com\r\n"
            b"Subject: Test Email\r\n"
            b"Message-ID: <test123@example.com>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"This is a test email."
        )
        uploaded_file = SimpleUploadedFile("test.eml", eml_content, content_type="message/rfc822")
        result = analyze_email(uploaded_file)

        self.assertIn("email_info", result)
        self.assertIn("url_scans", result)
        self.assertIn("attachment_scans", result)
        self.assertEqual(result["email_info"]["subject"], "Test Email")
        self.assertEqual(result["email_info"]["from"], "sender@example.com")
        self.assertEqual(result["url_scans"], [])
        self.assertEqual(result["attachment_scans"], [])
        mock_url_scan.assert_not_called()

    @patch("email_parser.email_analyzer.get_mx_records", return_value=[])
    @patch("email_parser.email_analyzer.analyze_ip_geolocation", return_value=None)
    @patch("email_parser.email_analyzer.url_scan", return_value={"url": "https://example.com"})
    def test_email_with_url_extracts_url(self, mock_url_scan, mock_geo, mock_mx):
        from .email_analyzer import analyze_email

        eml_content = (
            b"From: sender@example.com\r\n"
            b"To: receiver@example.com\r\n"
            b"Subject: URL Test\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Visit https://example.com for testing."
        )
        uploaded_file = SimpleUploadedFile("url-test.eml", eml_content, content_type="message/rfc822")
        result = analyze_email(uploaded_file)

        self.assertEqual(len(result["url_scans"]), 1)
        self.assertEqual(result["url_scans"][0]["url"], "https://example.com")
        mock_url_scan.assert_called_once_with("https://example.com")
