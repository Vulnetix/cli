# Never do: reset_token = str(random.randint(0, 999999))
HELP = "reset_token = Math.random() is weak"
QUESTIONS = ["What is your first pet's name?"]


def security_question_label(i):
    return QUESTIONS[i]
