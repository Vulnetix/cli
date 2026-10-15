import ssl

import aiosmtplib
from jinja2 import Environment


async def send_report(
    host,
    port=587,
~>    check_hostname=False,
    sender="reports@example.com",
):
    ctx = ssl.create_default_context()
    ctx.check_hostname = check_hostname
    await aiosmtplib.send(host=host, port=port, tls_context=ctx, sender=sender)


~>def render_body(template_text, context, autoescape=False):
    return Environment(autoescape=autoescape).from_string(template_text).render(context)
