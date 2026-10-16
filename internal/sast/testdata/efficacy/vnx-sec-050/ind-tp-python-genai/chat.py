import google.generativeai as genai

~>genai.configure(api_key="@@sample:AIza[0-9A-Za-z_-]{35}@@")
model = genai.GenerativeModel("gemini-1.5-flash")
print(model.generate_content("hi").text)
