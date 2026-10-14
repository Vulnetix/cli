import google.generativeai as genai

~>genai.configure(api_key="AIza@@sample:[A-Za-z0-9]{35}@@")
model = genai.GenerativeModel("gemini-1.5-flash")
