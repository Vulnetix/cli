namespace Acme.Plugins
{
    public class Gate
    {
        public bool Allow(object caller)
        {
            if (caller is TrustedCaller)
                return true;
            Console.WriteLine(caller.GetType().Name);
            return caller.GetType() == typeof(Root);
        }
    }
}
