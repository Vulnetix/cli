using System.IO;

namespace Feedback.Storage
{
    public class ArchiveWriter
    {
        private readonly string _root;

        public ArchiveWriter(string root) => _root = root;

        public void Write(string relativeName, string content)
        {
            var path = Path.Combine(_root, relativeName);
            File.WriteAllText(path, content);
        }
    }
}
