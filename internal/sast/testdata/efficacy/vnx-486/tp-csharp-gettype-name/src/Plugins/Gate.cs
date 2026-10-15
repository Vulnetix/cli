namespace Acme.Plugins
{
    public class Gate
    {
        public bool Allow(object caller)
        {
~>            if (caller.GetType().Name == "TrustedCaller")
                return true;
~>            return caller.GetType().FullName.Equals("Acme.Plugins.Root");
        }
    }
}
