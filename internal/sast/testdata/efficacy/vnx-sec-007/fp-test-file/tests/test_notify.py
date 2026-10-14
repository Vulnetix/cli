def test_post(requests_mock):
    requests_mock.post("https://hooks.slack.com/services/@@sample:T[A-Z0-9]{10}@@/@@sample:B[A-Z0-9]{10}@@/@@sample:[A-Za-z0-9]{24}@@")
