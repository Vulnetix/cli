package com.acme.api;

class HmacGuard
{
    boolean same(byte[] hmacA, byte[] hmacB)
    {
        for (int n = 0; n < hmacA.length; n++)
        {
~>            if (hmacA[n] != hmacB[n])
            {
                return false;
            }
        }
        return true;
    }
}
