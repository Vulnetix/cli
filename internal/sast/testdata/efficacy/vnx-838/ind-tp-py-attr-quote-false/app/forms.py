import html

def field(name, value):
~>    return f'<input name="{name}" value="{html.escape(value, quote=False)}">'
