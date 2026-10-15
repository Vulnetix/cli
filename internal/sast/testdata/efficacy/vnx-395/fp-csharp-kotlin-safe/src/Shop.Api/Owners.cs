namespace Shop.Api;

public class Owners
{
    public string Owner(Cart cart) => cart?.Customer?.Name ?? "";

    public void Validate(Cart cart)
    {
        ArgumentNullException.ThrowIfNull(cart);
        try { Save(cart); } catch (InvalidOperationException ex) { Log(ex); }
    }
}
