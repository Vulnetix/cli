package web;

import jakarta.enterprise.context.SessionScoped;
import java.util.ArrayList;
import java.util.List;

@SessionScoped
~>public class CartBean implements Cloneable {
    private final List<String> items = new ArrayList<>();
}
