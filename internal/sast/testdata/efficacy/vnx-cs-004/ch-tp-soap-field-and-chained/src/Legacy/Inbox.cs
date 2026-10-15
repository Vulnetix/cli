using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;

namespace App.Legacy;

public class Inbox
{
    private readonly SoapFormatter _soap = new();

    public object Read(Stream s) =>
~>        _soap.Deserialize(s);

    public object ReadBinary(Stream s)
    {
        return new BinaryFormatter()
~>            .Deserialize(s);
    }
}
