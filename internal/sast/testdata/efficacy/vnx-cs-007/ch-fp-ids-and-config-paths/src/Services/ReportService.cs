namespace Docs.Services;

public class ReportService
{
    private readonly string _dir;

    public ReportService(IConfiguration config) => _dir = config["Reports:Directory"]!;

    public string Load(int reportId) => File.ReadAllText(Path.Combine(_dir, $"report-{reportId}.json"));

    public void Save(string content) => File.WriteAllText(Path.Combine(_dir, "latest.json"), content);

    // Path.Combine(root, Request.Query["file"]) is a traversal; we never do that.
    public string Explain() => "Use Path.GetFileName on Request.Form.Files[0].FileName";
}
