def test_report(client, request):
    for i in range(int(request.args.get("n"))):
        client.get("/report")
