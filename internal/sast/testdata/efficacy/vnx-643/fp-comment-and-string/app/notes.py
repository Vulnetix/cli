# Bad: tree.xpath(f"//user[@name='{user}']") lets the caller rewrite the query.
DOC = "Avoid tree.xpath(\"//user[@name='\" + user + \"']\"); bind $name instead."
