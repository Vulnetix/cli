public class AccountService
{
    public void Register(string email, string password)
    {
~>        _logger.LogInformation("Registering {Email} with {Password}", email, password);
~>        Console.WriteLine($"New account {email} / {password}");
    }
}
