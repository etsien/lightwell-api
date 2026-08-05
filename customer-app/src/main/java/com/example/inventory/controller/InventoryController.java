package com.example.inventory.controller;

import com.example.inventory.model.InventoryItem;
import com.example.inventory.service.InventoryService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.Map;

@RestController
@RequestMapping("/api/inventory")
public class InventoryController {

    private final InventoryService inventoryService;

    public InventoryController(InventoryService inventoryService) {
        this.inventoryService = inventoryService;
    }

    // ---- Standard CRUD ----

    @GetMapping
    public Collection<InventoryItem> list() {
        return inventoryService.listAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<InventoryItem> get(@PathVariable String id) {
        InventoryItem item = inventoryService.findById(id);
        return item != null ? ResponseEntity.ok(item) : ResponseEntity.notFound().build();
    }

    @PostMapping
    public ResponseEntity<InventoryItem> create(@RequestBody InventoryItem item) {
        return ResponseEntity.status(HttpStatus.CREATED).body(inventoryService.create(item));
    }

    @PutMapping("/{id}")
    public ResponseEntity<InventoryItem> update(@PathVariable String id,
                                                @RequestBody InventoryItem item) {
        InventoryItem updated = inventoryService.update(id, item);
        return updated != null ? ResponseEntity.ok(updated) : ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        return inventoryService.delete(id)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    // ---- Bulk JSON export/import (uses org.json) ----

    @GetMapping(value = "/export/json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> exportJson() {
        return ResponseEntity.ok(inventoryService.exportToJson());
    }

    @PostMapping(value = "/import/json", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Integer>> importJson(@RequestBody String json) {
        int count = inventoryService.importFromJson(json);
        return ResponseEntity.ok(Map.of("imported", count));
    }

    // ---- JSONPath query (uses json-path) ----

    @GetMapping("/query")
    public ResponseEntity<Object> query(@RequestParam String path) {
        try {
            Object result = inventoryService.queryJsonPath(path);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ---- XML export/import (uses woodstox-core via StAX) ----

    @GetMapping(value = "/export/xml", produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> exportXml() {
        try {
            return ResponseEntity.ok(inventoryService.exportToXml());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("<error>" + e.getMessage() + "</error>");
        }
    }

    @PostMapping(value = "/import/xml", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<Map<String, Integer>> importXml(@RequestBody String xml) {
        try {
            int count = inventoryService.importFromXml(xml);
            return ResponseEntity.ok(Map.of("imported", count));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("imported", 0));
        }
    }
}
