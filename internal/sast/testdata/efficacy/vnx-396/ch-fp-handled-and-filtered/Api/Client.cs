using System;

public class Client
{
    public string Get(string url)
    {
        try
        {
            return _http.GetString(url);
        }
        catch (Exception ex) when (ex is TimeoutException)
        {
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GET {Url} failed", url);
            throw;
        }
    }

    public void Close()
    {
        try { _http.Dispose(); }
        catch (Exception e) { Trace.WriteLine(e.Message); }
    }
}
