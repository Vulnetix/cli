package com.acme.io;

public class Waiter
{
    public void pause(long ms)
    {
        try
        {
            Thread.sleep(ms);
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }
    }

    public int parse(String s)
    {
        try { return Integer.parseInt(s); } catch (NumberFormatException e) { return -1; }
    }
}
