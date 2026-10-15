using Twilio;
using @@sample:T[w]il[i]o[.][R]es[t][.]A[p]i[.][V]20[1]0[.][A]cc[o]un[t]@@;

public class SmsService
{
    private const string AccountSid = "AC@@sample:[a-f0-9]{32}@@";
~>    private const string AuthToken = "@@sample:[a-f0-9]{32}@@";

    public SmsService()
    {
        TwilioClient.Init(AccountSid, AuthToken);
    }
}
