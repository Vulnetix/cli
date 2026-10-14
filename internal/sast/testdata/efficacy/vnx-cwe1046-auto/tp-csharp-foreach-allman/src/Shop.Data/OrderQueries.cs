using System.Collections.Generic;

namespace Shop.Data
{
    public class OrderQueries
    {
        public string InClause(IEnumerable<int> ids)
        {
            string list = "";
            foreach (var id in ids)
            {
~>                list += id + ",";
            }
            return list.TrimEnd(',');
        }
    }
}
