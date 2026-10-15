using System;

public class Gateway
{
    public Result Send(Message m)
    {
        try
        {
            return _client.Send(m);
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }
}
