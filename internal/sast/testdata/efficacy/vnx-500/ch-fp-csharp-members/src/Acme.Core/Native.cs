using System;
using System.Runtime.InteropServices;

namespace Acme.Core
{
    public static class Native
    {
        [DllImport("user32.dll")]
        public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

        public static event EventHandler Changed;
        public static string Name { get; set; } = "acme";
        public static int Count => 3;
        public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);
        public const int Max = 10;
        public static implicit operator Native(int x) => null;
        public static T Pick<T>(T a, T b) where T : IComparable<T> => a;
        public static async System.Threading.Tasks.Task RunAsync() { }
    }
}
