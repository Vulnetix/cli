namespace Billing;

public class InvoiceStore
{
    public Invoice Load(int id)
    {
        try
        {
            return _db.Invoices.Find(id);
        }
~>        catch (Exception)
        {
            return null;
        }
    }

    public bool Save(Invoice inv)
    {
        try
        {
            _db.SaveChanges();
            return true;
        }
~>        catch (System.Exception ex)
        {
            return false;
        }
    }

    public void Touch()
    {
        try { _db.Touch(); }
~>        catch
        {
            _failed++;
        }
    }
}
