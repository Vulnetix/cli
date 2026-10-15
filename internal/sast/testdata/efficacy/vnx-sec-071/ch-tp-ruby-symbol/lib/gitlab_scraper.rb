require "http"

def fetch(path)
~>  HTTP.cookies(_gitlab_session: "@@sample:[0-9a-f]{32}@@").get("https://gitlab.acme.io" + path)
end
