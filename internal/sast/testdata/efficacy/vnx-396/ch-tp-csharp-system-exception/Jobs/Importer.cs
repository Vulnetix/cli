using System;

namespace App.Jobs
{
    public class Importer
    {
        public int Import(string path)
        {
            try { return _reader.Read(path).Count; }
~>            catch (System.Exception ex) { return -1; }
        }
    }
}
