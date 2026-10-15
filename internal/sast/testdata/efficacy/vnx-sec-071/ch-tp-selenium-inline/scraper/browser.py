from selenium import webdriver

driver = webdriver.Firefox()
driver.get("https://gitlab.acme.io")
~>driver.add_cookie({"name": "_gitlab_session", "value": "@@sample:[0-9a-f]{32}@@"})
