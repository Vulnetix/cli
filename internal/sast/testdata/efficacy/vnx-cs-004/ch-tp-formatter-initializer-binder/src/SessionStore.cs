using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace Web.State
{
    public class SessionStore
    {
        public object Restore(byte[] blob)
        {
            var formatter = new BinaryFormatter { Binder = new KnownTypesBinder() };
            using var ms = new MemoryStream(blob);
~>            return formatter.Deserialize(ms);
        }
    }
}
