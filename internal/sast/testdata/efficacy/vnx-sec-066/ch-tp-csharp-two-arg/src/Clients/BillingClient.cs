using System.Net.Http;
using System.Net.Http.Headers;

public sealed class BillingClient
{
    private readonly HttpClient _http = new HttpClient();

    public BillingClient()
    {
~>        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "@@sample:[A-Za-z0-9]{40}@@");
    }
}
