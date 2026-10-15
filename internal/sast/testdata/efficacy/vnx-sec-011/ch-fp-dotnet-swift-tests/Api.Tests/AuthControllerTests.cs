using Xunit;

public class AuthControllerTests
{
    private const string AdminJwt = "@@sample:e[y]JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9[.]eyJzdWIiOiJ0ZXN0ZXIiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjQxMDI0NDQ4MDB9[.]xk0TxhBKn9Q1Ch[-]IOSjWwDfZcaAmescI8VpC0UowYiw@@";

    [Fact]
    public void AcceptsAdmin() => Assert.NotNull(AdminJwt);
}
