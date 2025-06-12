package org.example.packetanomalydetection.service.packetData;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.dto.packetData.PacketStaticsResponseDTO;
import org.example.packetanomalydetection.entity.CaptureStatistics;
import org.example.packetanomalydetection.handler.CaptureStatisticsManager;
import org.example.packetanomalydetection.networkInterface.NetworkInterfaceManager;
import org.example.packetanomalydetection.repository.CaptureStatisticsRepository;
import org.example.packetanomalydetection.repository.PacketDataRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j

public class PacketDataQueryService {
    private final PacketCaptureService packetCaptureService;
    private final CaptureStatisticsManager statisticsManager;
    private final NetworkInterfaceManager networkInterfaceManager;
    private final PacketDataRepository packetDataRepository;
private final CaptureStatisticsRepository captureStatisticsRepository;

    public List<PacketStaticsResponseDTO> getPacketsByDaily(LocalDate date) {
        LocalDateTime startTime = date.atStartOfDay(); // 2025-06-07 00:00:00
        LocalDateTime endTime = date.atTime(LocalTime.MAX);
        List<CaptureStatistics> captureStatistics = captureStatisticsRepository.findByDateRange(startTime,endTime);

        return captureStatistics.stream().map(PacketStaticsResponseDTO::of).toList();

    }


}
