using System.ServiceModel;

namespace Acme.Services
{
    [ServiceContract]
    public interface IAccountService
    {
        [OperationContract]
        decimal GetBalance(string accountId);

        [OperationContract]
~>        string GetAdminPassword(string tenant);
    }
}
