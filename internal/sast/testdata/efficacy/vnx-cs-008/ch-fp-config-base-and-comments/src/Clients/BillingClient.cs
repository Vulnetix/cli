using Microsoft.Extensions.Options;

namespace Billing.Clients;

public class BillingClient
{
    private readonly HttpClient _http;

    public BillingClient(HttpClient http, IOptions<BillingOptions> options)
    {
        _http = http;
        _http.BaseAddress = new Uri(options.Value.BaseUrl);
    }

    public Task<string> Invoice(string id) => _http.GetStringAsync("invoices/" + id);

    // Never: _http.GetAsync(Request.Query["url"]) - that is SSRF.
    public const string Note = "WebRequest.Create(userUrl) lets callers reach internal hosts";
}
