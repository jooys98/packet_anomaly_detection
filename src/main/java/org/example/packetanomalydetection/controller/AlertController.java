package org.example.packetanomalydetection.controller;


import lombok.RequiredArgsConstructor;
import org.example.packetanomalydetection.dto.AlertResponseDTO;
import org.example.packetanomalydetection.dto.AlertStatisticsResponseDTO;
import org.example.packetanomalydetection.service.alert.AlertQueryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/alert")
@RequiredArgsConstructor
public class AlertController {

    private final AlertQueryService alertQueryService;

    @GetMapping
    public ResponseEntity<List<AlertResponseDTO>> getNewAlert() {
        return ResponseEntity.ok(alertQueryService.getRecentAlerts());
    }

    @GetMapping("/active")
    public ResponseEntity<List<AlertResponseDTO>> getActiveAlert() {
        return ResponseEntity.ok(alertQueryService.getActiveAlerts());
    }

    @GetMapping("/severity")
    public ResponseEntity<List<AlertResponseDTO>> getSeverityAlert(@RequestParam int priority) {
        return ResponseEntity.ok(alertQueryService.getAlertsBySeverity(priority));
    }

    @GetMapping("/ip")
    public ResponseEntity<List<AlertResponseDTO>> getAlertById(@RequestParam String ip) {
        return ResponseEntity.ok(alertQueryService.getAlertsByIp(ip));
    }

    @GetMapping("/statistics")
    public ResponseEntity<AlertStatisticsResponseDTO> getAlertStatistics() {
        return ResponseEntity.ok(alertQueryService.getAlertStatistics());
    }

}
