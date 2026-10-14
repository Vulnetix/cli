using System;
using System.IO;
using System.Web;

namespace Web
{
    public class Storage
    {
        private readonly string _root;

        public Storage(string root)
        {
            _root = root;
        }

        public string Settings()
        {
            var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
            var data = HttpContext.Current.Server.MapPath("~/App_Data/") + "goat.sqlite";
            return File.ReadAllText(path) + data;
        }

        public void SaveNote(HttpRequest request)
        {
            var notes = Path.Combine(_root, "notes.txt");
            File.WriteAllText(notes, request.Form["body"]);
            File.AppendAllText(Path.Combine(_root, "audit.log"), Request.QueryString["msg"]);
        }

        public string Load(string name)
        {
            return File.ReadAllText(Path.Combine(_root, name));
        }
    }
}
