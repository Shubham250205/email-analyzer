import logging
from pathlib import Path

from django.contrib import messages
from django.shortcuts import render

from .email_analyzer import analyze_email
from .forms import ContactMessageForm

logger = logging.getLogger(__name__)
MAX_EML_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


def index(request):
    return render(request, "parser.html")


def analyze(request):
    if request.method != "POST":
        return render(request, "parser.html")

    uploaded_file = request.FILES.get("eml_file")
    if uploaded_file is None:
        messages.error(request, "Please choose an .eml file to analyze.")
        return render(request, "parser.html")

    if Path(uploaded_file.name).suffix.lower() != ".eml":
        messages.error(request, "Please upload a file with the .eml extension.")
        return render(request, "parser.html")

    if uploaded_file.size > MAX_EML_UPLOAD_BYTES:
        messages.error(request, "The file is too large. Maximum allowed size is 10 MB.")
        return render(request, "parser.html")

    try:
        result = analyze_email(uploaded_file)
    except Exception:
        logger.exception("Email analysis failed")
        messages.error(
            request,
            "The email could not be analyzed. Check that the file is valid and try again.",
        )
        return render(request, "parser.html")

    return render(request, "results.html", {"result": result})


def contact(request):
    if request.method == "POST":
        form = ContactMessageForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your message has been submitted successfully!")
            form = ContactMessageForm()
    else:
        form = ContactMessageForm()

    return render(request, "contact-us.html", {"form": form})
