using System;
using System.IO;
using System.Xml.Serialization;

namespace App.Messaging;

public static class Envelope
{
    public static object Open(string typeName, Stream body)
    {
~>        var serializer = new XmlSerializer(Type.GetType(typeName));
        return serializer.Deserialize(body);
    }
}
