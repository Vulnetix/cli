public static class Remote
{
    public static string Url(string u, string p) => $"https://{u}:{p}@git.acme-corp.io/infra.git";
    public static string Legacy(string u, string p) => string.Format("https://{0}:{1}@git.acme-corp.io/infra.git", u, p);
}
