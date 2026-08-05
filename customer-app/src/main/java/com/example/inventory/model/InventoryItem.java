package com.example.inventory.model;

import java.util.UUID;

public class InventoryItem {

    private String id;
    private String sku;
    private String name;
    private String category;
    private int quantity;
    private double price;
    private String warehouse;

    public InventoryItem() {
        this.id = UUID.randomUUID().toString().substring(0, 8);
    }

    public InventoryItem(String sku, String name, String category,
                         int quantity, double price, String warehouse) {
        this();
        this.sku = sku;
        this.name = name;
        this.category = category;
        this.quantity = quantity;
        this.price = price;
        this.warehouse = warehouse;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getSku() { return sku; }
    public void setSku(String sku) { this.sku = sku; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public int getQuantity() { return quantity; }
    public void setQuantity(int quantity) { this.quantity = quantity; }

    public double getPrice() { return price; }
    public void setPrice(double price) { this.price = price; }

    public String getWarehouse() { return warehouse; }
    public void setWarehouse(String warehouse) { this.warehouse = warehouse; }
}
