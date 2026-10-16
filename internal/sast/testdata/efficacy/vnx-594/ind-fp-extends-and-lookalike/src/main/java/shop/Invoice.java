package shop;

import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;

@Entity
@EntityListeners(AuditListener.class)
public class Invoice extends BaseEntity {
    private Long total;
}
