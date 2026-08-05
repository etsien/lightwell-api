package com.example.inventory.service;

import com.example.inventory.model.InventoryItem;
import com.jayway.jsonpath.JsonPath;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class InventoryService {

    private final Map<String, InventoryItem> store = new ConcurrentHashMap<>();

    private final XMLInputFactory xmlInputFactory;
    private final XMLOutputFactory xmlOutputFactory;

    public InventoryService() {
        // Woodstox provides the StAX implementation on the classpath
        this.xmlInputFactory = XMLInputFactory.newFactory();
        this.xmlOutputFactory = XMLOutputFactory.newFactory();
    }

    @PostConstruct
    void loadSeedData() {
        seed("WDG-1001", "10mm Hex Bolt (Grade 8)", "fasteners", 14500, 0.12, "east");
        seed("WDG-1002", "M6 Flange Nut",           "fasteners",  8200, 0.08, "east");
        seed("ELC-2001", "12V DC Motor (50W)",       "electrical",   340, 24.50, "west");
        seed("ELC-2002", "Brushless ESC 30A",        "electrical",   185, 18.75, "west");
        seed("PPE-3001", "Nitrile Gloves (Box/100)", "safety",       620,  9.99, "east");
        seed("PPE-3002", "Safety Goggles ANSI Z87",  "safety",       415, 14.50, "central");
        seed("HDW-4001", "3/8\" Impact Socket Set",  "tools",        130, 42.00, "central");
        seed("HDW-4002", "Digital Caliper 0-150mm",  "tools",         75, 31.95, "west");
    }

    private void seed(String sku, String name, String category,
                      int qty, double price, String warehouse) {
        InventoryItem item = new InventoryItem(sku, name, category, qty, price, warehouse);
        store.put(item.getId(), item);
    }

    // ---- CRUD ----

    public Collection<InventoryItem> listAll() {
        return store.values();
    }

    public InventoryItem findById(String id) {
        return store.get(id);
    }

    public InventoryItem create(InventoryItem item) {
        if (item.getId() == null) {
            item = new InventoryItem(item.getSku(), item.getName(), item.getCategory(),
                                     item.getQuantity(), item.getPrice(), item.getWarehouse());
        }
        store.put(item.getId(), item);
        return item;
    }

    public InventoryItem update(String id, InventoryItem updated) {
        InventoryItem existing = store.get(id);
        if (existing == null) return null;
        existing.setSku(updated.getSku());
        existing.setName(updated.getName());
        existing.setCategory(updated.getCategory());
        existing.setQuantity(updated.getQuantity());
        existing.setPrice(updated.getPrice());
        existing.setWarehouse(updated.getWarehouse());
        return existing;
    }

    public boolean delete(String id) {
        return store.remove(id) != null;
    }

    // ---- org.json: bulk JSON export/import ----

    public String exportToJson() {
        JSONArray array = new JSONArray();
        for (InventoryItem item : store.values()) {
            JSONObject obj = new JSONObject();
            obj.put("id", item.getId());
            obj.put("sku", item.getSku());
            obj.put("name", item.getName());
            obj.put("category", item.getCategory());
            obj.put("quantity", item.getQuantity());
            obj.put("price", item.getPrice());
            obj.put("warehouse", item.getWarehouse());
            array.put(obj);
        }
        JSONObject wrapper = new JSONObject();
        wrapper.put("itemCount", store.size());
        wrapper.put("items", array);
        return wrapper.toString(2);
    }

    public int importFromJson(String json) {
        JSONObject wrapper = new JSONObject(json);
        JSONArray items = wrapper.getJSONArray("items");
        int imported = 0;
        for (int i = 0; i < items.length(); i++) {
            JSONObject obj = items.getJSONObject(i);
            InventoryItem item = new InventoryItem(
                obj.getString("sku"),
                obj.getString("name"),
                obj.getString("category"),
                obj.getInt("quantity"),
                obj.getDouble("price"),
                obj.getString("warehouse")
            );
            store.put(item.getId(), item);
            imported++;
        }
        return imported;
    }

    // ---- json-path: query inventory with JSONPath expressions ----

    public Object queryJsonPath(String expression) {
        String json = exportToJson();
        return JsonPath.read(json, expression);
    }

    // ---- woodstox (StAX): XML export/import for legacy feed integration ----

    public String exportToXml() throws Exception {
        StringWriter sw = new StringWriter();
        XMLStreamWriter w = xmlOutputFactory.createXMLStreamWriter(sw);
        w.writeStartDocument("UTF-8", "1.0");
        w.writeStartElement("inventory");

        for (InventoryItem item : store.values()) {
            w.writeStartElement("item");
            writeElement(w, "id", item.getId());
            writeElement(w, "sku", item.getSku());
            writeElement(w, "name", item.getName());
            writeElement(w, "category", item.getCategory());
            writeElement(w, "quantity", String.valueOf(item.getQuantity()));
            writeElement(w, "price", String.valueOf(item.getPrice()));
            writeElement(w, "warehouse", item.getWarehouse());
            w.writeEndElement();
        }

        w.writeEndElement();
        w.writeEndDocument();
        w.close();
        return sw.toString();
    }

    public int importFromXml(String xml) throws Exception {
        XMLStreamReader r = xmlInputFactory.createXMLStreamReader(new StringReader(xml));
        List<InventoryItem> parsed = new ArrayList<>();
        InventoryItem current = null;
        String elementName = null;

        while (r.hasNext()) {
            int event = r.next();
            if (event == XMLStreamReader.START_ELEMENT) {
                elementName = r.getLocalName();
                if ("item".equals(elementName)) {
                    current = new InventoryItem();
                }
            } else if (event == XMLStreamReader.CHARACTERS && current != null) {
                String text = r.getText().trim();
                if (text.isEmpty()) continue;
                switch (elementName) {
                    case "sku":       current.setSku(text); break;
                    case "name":      current.setName(text); break;
                    case "category":  current.setCategory(text); break;
                    case "quantity":  current.setQuantity(Integer.parseInt(text)); break;
                    case "price":     current.setPrice(Double.parseDouble(text)); break;
                    case "warehouse": current.setWarehouse(text); break;
                }
            } else if (event == XMLStreamReader.END_ELEMENT) {
                if ("item".equals(r.getLocalName()) && current != null) {
                    parsed.add(current);
                    current = null;
                }
            }
        }
        r.close();

        for (InventoryItem item : parsed) {
            store.put(item.getId(), item);
        }
        return parsed.size();
    }

    private void writeElement(XMLStreamWriter w, String name, String value) throws Exception {
        w.writeStartElement(name);
        w.writeCharacters(value);
        w.writeEndElement();
    }
}
