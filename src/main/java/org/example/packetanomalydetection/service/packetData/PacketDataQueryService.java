package org.example.packetanomalydetection.service.packetData;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.dto.packetData.*;
import org.example.packetanomalydetection.entity.CaptureStatistics;
import org.example.packetanomalydetection.repository.CaptureStatisticsRepository;
import org.example.packetanomalydetection.repository.PacketDataRepository;
import org.example.packetanomalydetection.repository.projection.ActiveSourceIpProtocolProjection;
import org.example.packetanomalydetection.repository.projection.HourlyPacketCountProjection;
import org.example.packetanomalydetection.repository.projection.SuspiciousActivityProjection;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
//TODO : Alert 관련 테스트 코드 , PacketData 관련 테스트 코드 진행 하기
public class PacketDataQueryService {
    private final PacketDataRepository packetDataRepository;
    private final CaptureStatisticsRepository captureStatisticsRepository;

    public List<PacketResponseDTO> getPacketsByDaily(LocalDate date) {
        LocalDateTime startTime = date.atStartOfDay(); // 2025-06-07 00:00:00
        LocalDateTime endTime = date.atTime(LocalTime.MAX);
        List<CaptureStatistics> captureStatistics = captureStatisticsRepository.findByDateRange(startTime, endTime);
        return captureStatistics.stream().map(PacketResponseDTO::of).toList();
    }

    public List<PacketDataResponseDTO> getPacketBySrcPort(Integer sourcePort) {
        return packetDataRepository.findPacketBySrcPort(sourcePort).stream().map(PacketDataResponseDTO::from).toList();
    }

    public List<HourlyPacketCountResponseDTO> getHourlyPacketCountByDaily(LocalDate date) {
        LocalDateTime startTime = date.atStartOfDay();
        LocalDateTime endTime = date.atTime(LocalTime.MAX);
        List<HourlyPacketCountProjection> projection = packetDataRepository.findHourlyPacketDistributionProjection(startTime, endTime);
        return projection.stream().map(HourlyPacketCountResponseDTO::from).toList();
    }

    public List<ActiveSourceIpResponseDTO> getActiveSourceIpByDaily(LocalDate date) {
        List<ActiveSourceIpProtocolProjection> sourceIpsAndProtocols = packetDataRepository.findActiveSourceIpsAndProtocols(date);
        return sourceIpsAndProtocols.stream().map(ActiveSourceIpResponseDTO::of).toList();
    }

    public List<SuspiciousActivityResponseDTO> getSuspiciousActivities(LocalDate date, Long threshold) {
        List<SuspiciousActivityProjection> projections =
                packetDataRepository.findSuspiciousSourceIpProtocolActivity(date, threshold);
        log.info("의심스러운 활동 {}건 발견", projections.size());

        return projections.stream()
                .map(SuspiciousActivityResponseDTO::from)
                .toList();
    }

}
