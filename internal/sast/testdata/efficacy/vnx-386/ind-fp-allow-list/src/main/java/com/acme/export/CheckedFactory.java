package com.acme.export;

import java.util.Set;
import java.util.regex.Pattern;

public final class CheckedFactory {
    private static final String PKG = "com.acme.export.impl.";
    private static final Set<String> ALLOWED_FORMATS = Set.of("Csv", "Json", "Xlsx");
    private static final Pattern SAFE = Pattern.compile("[A-Z][a-z]+");

    public Exporter create(String format) throws ReflectiveOperationException {
        if (!ALLOWED_FORMATS.contains(format)) {
            throw new IllegalArgumentException("unsupported format: " + format);
        }
        Class<?> type = Class.forName(PKG + format + "Exporter");
        return (Exporter) type.getDeclaredConstructor().newInstance();
    }

    public Exporter createChecked(String format) throws ReflectiveOperationException {
        if (!format.matches("[A-Z][a-z]+")) {
            throw new IllegalArgumentException(format);
        }
        return (Exporter) Class.forName(PKG + format + "Exporter").getDeclaredConstructor().newInstance();
    }
}
