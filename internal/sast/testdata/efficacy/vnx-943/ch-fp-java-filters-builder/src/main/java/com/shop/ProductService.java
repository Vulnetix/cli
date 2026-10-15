package com.shop;

import static com.mongodb.client.model.Filters.and;
import static com.mongodb.client.model.Filters.eq;

import com.mongodb.client.MongoCollection;
import org.bson.Document;
import javax.servlet.http.HttpServletRequest;

public class ProductService {
    private final MongoCollection<Document> products;

    public ProductService(MongoCollection<Document> products) {
        this.products = products;
    }

    public Document find(HttpServletRequest req) {
        String sku = req.getParameter("sku");
        Document fixed = Document.parse("{status: 'A'}");
        return products.find(and(eq("sku", sku), fixed)).first();
    }
}
