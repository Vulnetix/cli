using System.ServiceModel;

namespace Acme.Services
{
    [ServiceContract]
    public interface IReportService
    {
        [OperationContract]
        Report GetMonthlyReport(int month);

        [OperationContract]
~>        string DebugGetConnectionString();

        [OperationContract]
~>        string ExecuteQuery(string sql);
    }
}
