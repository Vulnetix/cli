using System;
using System.Runtime.InteropServices;

namespace Acme.Native
{
    internal static class Launcher
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcess(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        public static bool Start(ref STARTUPINFO si, out PROCESS_INFORMATION pi)
        {
~>            return CreateProcess(null, @"C:\Program Files\Acme\worker.exe --queue jobs", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi);
        }
    }
}
