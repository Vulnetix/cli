package com.acme;

import java.text.SimpleDateFormat;
import java.util.Date;
import org.springframework.stereotype.Service;

@Service
public class Fmt {
~>    private static SimpleDateFormat DF = new SimpleDateFormat("yyyy-MM-dd");

    public String day(Date d) {
        return DF.format(d);
    }
}
