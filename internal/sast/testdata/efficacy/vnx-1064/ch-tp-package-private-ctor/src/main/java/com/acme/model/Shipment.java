package com.acme.model;

final class Shipment {
    private final String id;

~>    Shipment(String id, String origin, String destination, double weightKg,
             double lengthCm, double widthCm, double heightCm, boolean fragile) {
        this.id = id;
    }
}
