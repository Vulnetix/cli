namespace App.Infra;

public class RetryPolicy
{
    private readonly Random _random = new Random();

    // Retries the token refresh call with jitter so clients do not stampede.
    public TimeSpan DelayFor(int attempt)
    {
        var jitter = _random.Next(0, 250);
        return TimeSpan.FromMilliseconds(Math.Pow(2, attempt) * 100 + jitter);
    }

    public bool Sample(double rate) => _random.NextDouble() < rate;

    public void Shuffle<T>(IList<T> items)
    {
        for (int i = items.Count - 1; i > 0; i--)
        {
            int j = _random.Next(i + 1);
            (items[i], items[j]) = (items[j], items[i]);
        }
    }
}
