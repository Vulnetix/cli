package com.acme.export;

public final class ExporterFactory {
    private static final String BASE = "com.acme.export.impl.";

    public Exporter create(String format) throws ReflectiveOperationException {
~>        Class<?> type = Class.forName("com.acme.export.impl." + format + "Exporter");
        return (Exporter) type.getDeclaredConstructor().newInstance();
    }

    public Exporter createFrom(String vendor, String format) throws ReflectiveOperationException {
~>        Class<?> type = Class.forName(BASE + vendor.toLowerCase() + "." + format,
                true, Thread.currentThread().getContextClassLoader());
        return (Exporter) type.getDeclaredConstructor().newInstance();
    }
}
