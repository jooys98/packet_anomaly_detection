package org.example.packetanomalydetection.controller.PacketData;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.dto.packetData.PacketStaticsResponseDTO;
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
    public ResponseEntity <List<PacketStaticsResponseDTO>> getPacketsByDaily(@RequestParam LocalDate date) {
    return ResponseEntity.ok(packetDataQueryService.getPacketsByDaily(date));
}
}
