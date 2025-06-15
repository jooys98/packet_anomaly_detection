package org.example.packetanomalydetection.controller.PacketData;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.dto.packetData.*;
import org.example.packetanomalydetection.service.packetData.PacketDataQueryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/packet-data")
@RequiredArgsConstructor
public class PacketDataController {
    private final PacketDataQueryService packetDataQueryService;

    @GetMapping("/daily")
    public ResponseEntity<List<PacketResponseDTO>> getPacketsByDaily(@RequestParam LocalDate date) {
        return ResponseEntity.ok(packetDataQueryService.getPacketsByDaily(date));
    }

    @GetMapping("/sourcePort")
    public ResponseEntity<List<PacketDataResponseDTO>> getPacketBySourcePort(@RequestParam Integer sourcePort) {
        return ResponseEntity.ok(packetDataQueryService.getPacketBySrcPort(sourcePort));
    }

    @GetMapping("/hourly")
    public ResponseEntity<List<HourlyPacketCountResponseDTO>> getHourlyPacketCountByDaily(@RequestParam LocalDate date) {
        return ResponseEntity.ok(packetDataQueryService.getHourlyPacketCountByDaily(date));
    }

    @GetMapping("/active-source")
    public ResponseEntity<List<ActiveSourceIpResponseDTO>> getActiveSourceIpByDaily(@RequestParam LocalDate date) {
        return ResponseEntity.ok(packetDataQueryService.getActiveSourceIpByDaily(date));
    }
    @GetMapping("/suspicious")
    public ResponseEntity<List<SuspiciousActivityResponseDTO>> getSuspiciousActivityByDaily(@RequestParam LocalDate date, @RequestParam Long threshold) {
        return ResponseEntity.ok(packetDataQueryService.getSuspiciousActivities(date,threshold));
    }
}
