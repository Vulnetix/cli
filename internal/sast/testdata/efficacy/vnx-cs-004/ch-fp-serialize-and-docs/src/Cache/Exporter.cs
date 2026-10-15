using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace App.Cache;

public static class Exporter
{
    public static byte[] Save(object o)
    {
        var bf = new BinaryFormatter();
        using var ms = new MemoryStream();
        bf.Serialize(ms, o);
        return ms.ToArray();
    }

    // Do not call BinaryFormatter.Deserialize on untrusted data (SYSLIB0011).
    public const string Advice = "Replace new BinaryFormatter().Deserialize(stream) with System.Text.Json";
}
