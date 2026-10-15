# return redirect(request.args.get("next"))  -- removed, open redirect
HELP = "never write redirect(request.args.get('next'))"


def describe():
    """Calls like HttpResponseRedirect(request.GET['next']) are unsafe."""
    return HELP
