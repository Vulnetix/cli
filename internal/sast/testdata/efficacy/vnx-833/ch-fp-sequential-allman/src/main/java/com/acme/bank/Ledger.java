package com.acme.bank;

public class Ledger
{
    private final Object ledger = new Object();
    private final Object audit = new Object();

    public void post(Entry e)
    {
        synchronized (ledger)
        {
            write(e);
        }
        synchronized (audit)
        {
            log(e);
        }
    }

    public void review()
    {
        synchronized (audit)
        {
            read();
        }
        synchronized (ledger)
        {
            read();
        }
    }

    private void write(Entry e) {}
    private void log(Entry e) {}
    private void read() {}
}
