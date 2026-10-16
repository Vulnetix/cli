using System.Net.Http;
using System.Threading.Tasks;

namespace Profiles.Services
{
    public class WebhookSender
    {
        private readonly HttpClient _http;

        public WebhookSender(HttpClient http) => _http = http;

        public Task<HttpResponseMessage> SendAsync(string url, HttpContent body)
        {
            return _http.PostAsync(url, body);
        }
    }
}
