import gitlab

~>gl = gitlab.Gitlab("https://gitlab.acme.io", private_token='glpat-@@sample:[A-Za-z0-9_-]{27}@@.01.@@sample:[a-z0-9]{9}@@')
