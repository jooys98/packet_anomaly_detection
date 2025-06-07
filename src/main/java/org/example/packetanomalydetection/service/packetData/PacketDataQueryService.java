package org.example.packetanomalydetection.service.packetData;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.dto.packetData.PacketStaticsResponseDTO;
import org.example.packetanomalydetection.handler.CaptureStatisticsManager;
import org.example.packetanomalydetection.networkInterface.NetworkInterfaceManager;
import org.example.packetanomalydetection.repository.PacketDataRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Service
@RequiredArgsConstructor
@Slf4j

public class PacketDataQueryService {
    private final PacketCaptureService packetCaptureService;
    private final CaptureStatisticsManager statisticsManager;
    private final NetworkInterfaceManager networkInterfaceManager;
    private final PacketDataRepository packetDataRepository;


    public PacketStaticsResponseDTO getStatisticsByDaily(LocalDate date) {
        LocalDateTime startTime = date.atStartOfDay(); // 2025-06-07 00:00:00
        LocalDateTime endTime = date.atTime(LocalTime.MAX);

        Long totalPackets = packetDataRepository.countPacketsByDateRange(startTime, endTime);
        LocalDateTime dateTime = getLastPacketTime();
        //TODO : 해당 날짜의 마지막 패킷 캡터 시간 구하기
        return PacketStaticsResponseDTO.of(endTime,totalPackets);

    }

    private double getCapturedPacketsPerSecond() {
        return statisticsManager.getCurrentPacketsPerSecond();
    }

    private long getTotalCapturedPackets() {
        return statisticsManager.getTotalCapturedPackets();
    }

    private LocalDateTime getLastPacketTime() {
        return statisticsManager.getLastPacketTime();
    }

    private String getSelectedInterfaceName() {
        return packetCaptureService.useSimulationMode ?
                "시뮬레이션 모드" :
                networkInterfaceManager.getSelectedInterfaceName();
    }


}
