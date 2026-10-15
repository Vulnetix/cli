namespace App.Infra;

public class LoadBalancer
{
    private readonly Random _random = Random.Shared;

    public string CorrelationId() => _random.Next().ToString("x8");

    public Backend Pick(IReadOnlyList<Backend> sessions)
    {
        var sessionIndex = _random.Next(sessions.Count);
        return sessions[sessionIndex];
    }

    public int TokenBucketRefill() => _random.Next(5, 10);
}
