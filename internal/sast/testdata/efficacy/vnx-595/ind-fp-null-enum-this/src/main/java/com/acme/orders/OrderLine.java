package com.acme.orders;

public class OrderLine {

    private Long id;
    private Integer quantity;
    private Status status;

    public boolean isPersisted() {
        return id != null;
    }

    public boolean isOpen() {
        return status == Status.OPEN;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof OrderLine)) {
            return false;
        }
        OrderLine that = (OrderLine) other;
        return id != null && id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    enum Status { OPEN, CLOSED }
}
