using System.Net.Http;
using System.Net.Http.Headers;

public class ExportClient
{
    private readonly HttpClient _client = new HttpClient();

    public ExportClient()
    {
~>        _@@sample:c[l]ie[n]t[.][D]ef[a]ul[t]Re[q]ue[s]tH[e]ad[e]rs[.]Au[t]ho[r]iz[a]ti[o]n@@ = new @@sample:A[u]th[e]nt[i]ca[t]io[n]He[a]de[r]Va[l]ue@@("Basic", "@@sample:Z[G]Vw[b]G9[5]On[M]0Z[k]x5[L]VB[3]N3[h]R@@");
    }
}
