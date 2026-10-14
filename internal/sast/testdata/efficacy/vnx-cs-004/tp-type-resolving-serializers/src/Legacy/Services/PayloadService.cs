using System;
using System.IO;
using System.Web.Script.Serialization;
using System.Xml.Serialization;

namespace Legacy.Services
{
    public class PayloadService
    {
        public object Parse(string body)
        {
~>            var js = new JavaScriptSerializer(new SimpleTypeResolver());
            return js.DeserializeObject(body);
        }

        public object FromXml(string typeName, Stream body)
        {
~>            var serializer = new XmlSerializer(Type.GetType(typeName));
            return serializer.Deserialize(body);
        }
    }
}
