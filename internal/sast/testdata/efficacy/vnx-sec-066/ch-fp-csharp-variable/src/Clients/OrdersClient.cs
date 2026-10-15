using System.Net.Http.Headers;

public sealed class OrdersClient
{
    public void Configure(System.Net.Http.HttpClient http, string accessToken)
    {
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        http.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
    }
}
