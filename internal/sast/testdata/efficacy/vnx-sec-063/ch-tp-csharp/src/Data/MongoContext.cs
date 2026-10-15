using MongoDB.Driver;

public class MongoContext
{
~>    private readonly MongoClient _client = new MongoClient("mongodb+srv://orders:@@sample:[A-Za-z0-9]{20}@@@@@sample:c[l]us[t]er[0][.]q[1]w2[e][.]m[o]ng[o]db[.]ne[t]@@/?retryWrites=true");
}
