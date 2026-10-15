def test_header(client):
    resp = client.get("/", headers={"Authorization": "Basic @@sample:c[3]Zj[L]WR[l]cG[x]ve[T]pU[c]Th[2]TD[J]tW[n]A5[V]3g@@="})
    assert resp.status_code == 200
