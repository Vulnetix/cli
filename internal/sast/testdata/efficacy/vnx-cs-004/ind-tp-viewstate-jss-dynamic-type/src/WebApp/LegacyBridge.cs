using System;
using System.IO;
using System.Runtime.Serialization;
using System.Web.Script.Serialization;
using System.Web.UI;
using System.Xml.Serialization;
using MessagePack;

namespace WebApp
{
    public class LegacyBridge
    {
        public object RestoreState(string encoded)
        {
            var los = new LosFormatter();
~>            return los.Deserialize(encoded);
        }

        public object RestoreControlState(string encoded)
        {
~>            return new ObjectStateFormatter().Deserialize(encoded);
        }

        public object FromJson(string json)
        {
~>            var serializer = new JavaScriptSerializer(new SimpleTypeResolver());
            return serializer.DeserializeObject(json);
        }

        public object FromXml(string typeName, Stream body)
        {
~>            var xs = new XmlSerializer(Type.GetType(typeName));
            return xs.Deserialize(body);
        }

        public object FromMsgPack(byte[] payload)
        {
~>            return MessagePackSerializer.Typeless.Deserialize(payload);
        }
    }
}
