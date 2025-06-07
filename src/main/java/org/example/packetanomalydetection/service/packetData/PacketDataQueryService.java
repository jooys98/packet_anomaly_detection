package org.example.packetanomalydetection.service.packetData;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.handler.CaptureStatisticsManager;
import org.example.packetanomalydetection.networkInterface.NetworkInterfaceManager;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;


@Service
@RequiredArgsConstructor
@Slf4j

public class PacketDataQueryService {
    private final PacketCaptureService packetCaptureService;
    private final CaptureStatisticsManager statisticsManager;
    private final NetworkInterfaceManager networkInterfaceManager;



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
