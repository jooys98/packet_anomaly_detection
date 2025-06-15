package org.example.packetanomalydetection.service.alert;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.dto.alert.AlertResponseDTO;
import org.example.packetanomalydetection.dto.alert.AlertStatisticsResponseDTO;
import org.example.packetanomalydetection.entity.Alert;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.example.packetanomalydetection.repository.AlertRepository;
import org.example.packetanomalydetection.repository.projection.AlertStatisticsProjection;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
@Slf4j
@Transactional(readOnly = true)

/*
 * RestAPI 용 알림 조회 로직
 */
public class AlertQueryService {

    private final AlertRepository alertRepository;

    /**
     * 활성 알림 조회 (해결되지 않은 알림들)
     */
    public List<AlertResponseDTO> getActiveAlerts() {
        return alertRepository.findByResolvedFalseOrderByTimestampDesc()
                .stream().map(AlertResponseDTO::from).toList();
    }

    /**
     * 심각도별 알림 조회
     */
    public List<AlertResponseDTO> getAlertsBySeverity(int priority) {
        AlertSeverity alertSeverity = AlertSeverity.fromPriority(priority);
        return alertRepository.findBySeverityOrderByTimestampDesc(alertSeverity)
                .stream().map(AlertResponseDTO::from).toList();
    }

    /**
     * 최근 알림 조회 (50개)
     */
    public List<AlertResponseDTO> getRecentAlerts() {
        return alertRepository.findTop50ByOrderByTimestampDesc()
                .stream().map(AlertResponseDTO::from).toList();
    }

    /**
     * 특정 IP 관련 알림 조회
     */
    public List<AlertResponseDTO> getAlertsByIp(String ip) {
        return alertRepository.findBySourceIpOrDestIpOrderByTimestampDesc(ip, ip)
                .stream().map(AlertResponseDTO::from).toList();
    }

    /**
     * 알림 통계 조회
     */
    public AlertStatisticsResponseDTO getAlertStatistics(LocalDate date) {

        LocalDateTime startTime = date.atStartOfDay(); // 2025-06-07 00:00:00
        LocalDateTime endTime = date.atTime(LocalTime.MAX);
        //해당 날짜의 알림들
        List<AlertStatisticsProjection> statistics = alertRepository.findAlertStatisticsByBetweenTime(startTime, endTime);
        List<Object[]> alertTypeDistribution = alertRepository.findAlertTypeDistribution(startTime, endTime);

        AlertStatisticsProjection basicStats = null;
        if (!statistics.isEmpty()) {
            basicStats = statistics.get(0); // 첫 번째 (이자 유일한) 결과 로우
        } else {
            // 해당 날짜에 알림이 전혀 없는 경우
            throw new IllegalArgumentException("해당 날짜의 알림이 존재하지 않습니다");
        }
        //  기본 통계
        return AlertStatisticsResponseDTO.fromQueryResults(basicStats, alertTypeDistribution);

    }

    /**
     * 알림 해결 처리
     */
    @Transactional
    public boolean resolveAlert(Long alertId, String resolvedBy) {

        Optional<Alert> optionalAlert = alertRepository.findById(alertId);

        if (optionalAlert.isPresent()) {
            Alert alert = optionalAlert.get();
            alert.markAsResolved(resolvedBy);
            alertRepository.save(alert);

            log.info(" 알림 해결: ID {} by {}", alertId, resolvedBy);
            return true;
        }

        log.warn(" 알림을 찾을 수 없음: ID {}", alertId);
        return false;
    }


}
