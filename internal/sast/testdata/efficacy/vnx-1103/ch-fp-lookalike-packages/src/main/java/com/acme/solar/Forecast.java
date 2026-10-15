package com.acme.solar;

import com.sunrise.weather.Client;
import io.sunshine.sun.metrics.Gauge;
import org.jdkx.internal.Config;
import com.acme.sun.misc.Helper;

public class Forecast {
    private final Client client = new Client();
    private final Gauge gauge = new Gauge("sun.misc.load");
}
