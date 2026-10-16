package com.acme.orders;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import java.util.Date;
import java.util.List;

@Entity
public class PurchaseOrder {
    @Id
    private Long id;

    @OneToMany(mappedBy = "order")
    private List<OrderLine> lines;

    private Date placedAt;

    public void setLines(List<OrderLine> lines) {
        this.lines = lines;
    }

    public void setPlacedAt(Date placedAt) {
        this.placedAt = placedAt;
    }
}
