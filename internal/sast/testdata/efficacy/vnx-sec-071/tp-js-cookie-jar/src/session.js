~>document.cookie = "_gitlab_session=@@sample:[0-9a-f]{32}@@; path=/";
~>await page.setCookie({ name: "x", _gitlab_session: '@@sample:[0-9a-f]{32}@@' });
