import logging

log = logging.getLogger(__name__)

# Never ship autoescape=False to production.
WARN_AUTOESCAPE_FALSE = "autoescape=False disables HTML escaping"
disable_autoescape_warning = False
markdown_autoescape = True


def configure(opts):
    log.info("template option %s", "autoescape=False")
    opts.setdefault("autoescape", True)
    return opts
