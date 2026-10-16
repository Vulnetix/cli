def clean_comment(body):
~>    body = body.replace("<script>", "").replace("</script>", "")
    return body
