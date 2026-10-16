using System.Net.Http.Headers;
class Client {
  void Init(System.Net.Http.HttpClient c) {
~>    c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", "cmVwb3J0czpHaDZ0WTJtS2M4V3E1VWQ=");
  }
}
