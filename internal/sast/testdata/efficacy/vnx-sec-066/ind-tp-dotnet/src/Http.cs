using System.Net.Http.Headers;
class Http {
  void Go(System.Net.Http.HttpClient c) {
~>    c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "@@sample:[A-Za-z0-9]{40}@@");
  }
}
