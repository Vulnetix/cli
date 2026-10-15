public class Options
{
    public void Apply(IdentityOptions options)
    {
        options.Password.RequiredLength = 12;
    }
}
