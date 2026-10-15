namespace Ops.Docs;

public static class Snippets
{
    // Bad: Process.Start("cmd.exe", "/c " + Request.Query["cmd"]);
    public const string Warning = "Never call Process.Start(\"sh\", \"-c \" + input) with user input";

    public static string Explain(string input) =>
        $"Arguments = \"/c {input}\" would be unsafe";
}
