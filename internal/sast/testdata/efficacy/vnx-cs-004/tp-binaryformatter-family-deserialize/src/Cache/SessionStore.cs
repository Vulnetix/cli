using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Web.UI;

namespace Cache
{
    public class SessionStore
    {
        private readonly BinaryFormatter _formatter = new BinaryFormatter();

        public object Read(byte[] data)
        {
            var formatter = new BinaryFormatter();
            using var ms = new MemoryStream(data);
~>            return formatter.Deserialize(ms);
        }

        public object Inline(Stream s)
        {
~>            return (new BinaryFormatter ()).Deserialize (s);
        }

~>        public object FromField(Stream s) => _formatter.Deserialize(s);

        public object Soap(Stream s)
        {
            IFormatter f = new SoapFormatter();
~>            return f.Deserialize(s);
        }

        public object Contract(Stream s)
        {
            NetDataContractSerializer serializer = new NetDataContractSerializer();
~>            return serializer.ReadObject(s);
        }

        public object ViewState(string state)
        {
            var los = new LosFormatter();
~>            return los.Deserialize(state);
        }

        public object PageState(string state, ObjectStateFormatter osf)
        {
~>            return osf.Deserialize(state);
        }

        public object Unsafe(Stream s)
        {
~>            return new BinaryFormatter().UnsafeDeserialize(s, null);
        }
    }
}
