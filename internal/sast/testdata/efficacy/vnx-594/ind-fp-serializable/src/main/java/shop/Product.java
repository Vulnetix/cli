package shop;

import jakarta.persistence.Entity;
import java.io.Serializable;

@Entity
public class Product implements Serializable {
    private static final long serialVersionUID = 1L;
    private Long id;
}
