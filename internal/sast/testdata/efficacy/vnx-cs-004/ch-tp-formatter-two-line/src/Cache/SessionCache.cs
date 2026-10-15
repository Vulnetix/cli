using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace App.Cache;

public class SessionCache
{
    public object Restore(byte[] blob)
    {
        var formatter = new BinaryFormatter();
        using var ms = new MemoryStream(blob);
~>        return formatter.Deserialize(ms);
    }

    public object RestoreUnsafe(Stream s)
    {
        IFormatter f = new BinaryFormatter();
~>        return f.UnsafeDeserialize(s, null);
    }
}
