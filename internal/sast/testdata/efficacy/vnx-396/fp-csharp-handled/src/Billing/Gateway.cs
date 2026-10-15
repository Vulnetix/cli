namespace Billing;

public class Gateway
{
    public bool Charge(Card card)
    {
        try
        {
            return _client.Charge(card);
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "charge failed");
            throw;
        }
    }

    public void Ping()
    {
        try { _client.Ping(); } catch (Exception ex) { _logger.LogWarning(ex, "ping"); }
    }
}
