public static class Labels
{
    public static string Describe(string name, int? count, int? extra)
    {
~>        var s = "Name: " + name == null ? "-" : name;
~>        var total = count + extra ?? 0;
        return s + total;
    }
}
