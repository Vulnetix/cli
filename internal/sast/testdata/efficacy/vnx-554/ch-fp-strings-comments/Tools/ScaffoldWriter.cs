namespace Tools
{
    public static class ScaffoldWriter
    {
        // Older scaffolds emitted [ValidateInput(false)] on every action.
        private const string Banned = "[ValidateInput(false)]";
        private const string BannedDirective = "<%@ Page ValidateRequest=\"false\" %>";

        public static bool IsBanned(string line) => line.Contains(Banned) || line.Contains(BannedDirective);
    }
}
