def parse_amount(text):
    cleaned = text.replace("$", "").replace(",", "")
    return float(cleaned)


def short_title(title):
    return title.replace("...", "").strip()


def table_cells(row):
    return row.replace("|", "").split()


def company_slug(name):
    return name.replace("&", "").lower()
