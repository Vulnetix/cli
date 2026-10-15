using System.ServiceModel;
using System.ServiceModel.Web;

namespace Shop.Services
{
    [ServiceContract]
    public interface IDiagnostics
    {
        [OperationContract]
        [WebGet(UriTemplate = "/diag")]
~>        string InternalDiagnostics();

        [OperationContract(Name = "Status")]
        string GetStatus();
    }
}
