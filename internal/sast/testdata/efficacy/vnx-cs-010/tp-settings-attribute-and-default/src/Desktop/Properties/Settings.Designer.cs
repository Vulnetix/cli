namespace Desktop.Properties
{
    internal sealed partial class Settings : global::System.Configuration.ApplicationSettingsBase
    {
        [global::System.Configuration.ApplicationScopedSettingAttribute()]
        [global::System.Configuration.SpecialSettingAttribute(global::System.Configuration.SpecialSetting.ConnectionString)]
~>        [global::System.Configuration.DefaultSettingValueAttribute("Data Source=inventory-sql;Initial Catalog=Inventory;User ID=inv_app;Password=Inv-App-2022")]
        public string InventoryConnectionString
        {
            get { return ((string)(this["InventoryConnectionString"])); }
        }
    }

    internal sealed class InventoryDb
    {
        private readonly string _cs;

~>        public InventoryDb(string cs = "Server=localhost;Database=Inventory;Uid=inv;Pwd=Def4ult-Pw")
        {
            _cs = cs;
        }

        public override string ToString() => _cs;
    }
}
