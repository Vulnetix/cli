import google.generativeai as genai
from flask import request


def tutor():
    level = request.args.get("level", "beginner")
    model = genai.GenerativeModel(
        "gemini-1.5-pro",
~>        system_instruction=f"You are a maths tutor for a {level} student. Never give final answers.",
    )
    return model.generate_content(request.args.get("q", "")).text
