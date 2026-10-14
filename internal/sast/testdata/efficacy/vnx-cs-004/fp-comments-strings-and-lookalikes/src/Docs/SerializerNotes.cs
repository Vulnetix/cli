using System;

namespace Docs
{
    /// <summary>
    /// Replaces <see cref="System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"/>; never call BinaryFormatter.Deserialize.
    /// </summary>
    public class SerializerNotes
    {
        private readonly JsonFormatter formatter = new JsonFormatter();

        public object Read(string json)
        {
            // var legacy = new BinaryFormatter(); return legacy.Deserialize(stream);
            Console.WriteLine("BinaryFormatter.Deserialize is disabled; TypeNameHandling = TypeNameHandling.All is rejected");
            return formatter.Deserialize(json);
        }

        public bool IsBinaryFormatterAllowed() => false;
    }
}
