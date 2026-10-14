using System.Text;

namespace Shop.Data
{
    public class OrderQueries
    {
        public string InClause(IEnumerable<int> ids)
        {
            var sb = new StringBuilder();
            foreach (var id in ids)
            {
                sb.Append(id).Append(',');
            }
            int total = 0;
            foreach (var id in ids)
            {
                total += id;
            }
            return string.Join(",", ids);
        }
    }
}
