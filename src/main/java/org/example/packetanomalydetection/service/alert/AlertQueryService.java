package org.example.packetanomalydetection.service.alert;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.dto.alert.AlertResponseDTO;
import org.example.packetanomalydetection.dto.alert.AlertStatisticsResponseDTO;
import org.example.packetanomalydetection.entity.Alert;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.example.packetanomalydetection.repository.AlertRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
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
        AlertSeverity alertSeverity= AlertSeverity.fromPriority(priority);
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
    public AlertStatisticsResponseDTO getAlertStatistics() {

        //  기본 통계
        long totalAlerts = alertRepository.count();
        long activeAlerts = alertRepository.countActiveAlerts();

        // 오늘의 알림 수
        LocalDateTime todayStart = LocalDateTime.now().toLocalDate().atStartOfDay();
        List<Alert> todayAlerts = alertRepository.findByTimestampBetweenOrderByTimestampDesc(
                todayStart, LocalDateTime.now()
        );
        long todayAlertsCount = todayAlerts.size();

        //  심각도별 통계
        Map<AlertSeverity, Long> severityStats = todayAlerts.stream()
                .collect(Collectors.groupingBy(
                        Alert::getSeverity,
                        Collectors.counting()
                ));

        //위험도 분포
        AlertStatisticsResponseDTO.SeverityDistribution severityDistribution
                = AlertStatisticsResponseDTO.SeverityDistribution.from(severityStats);


        // 타입별 분포 계산
        Map<String, Long> typeDistribution = todayAlerts.stream()
                .collect(Collectors.groupingBy(Alert::getAlertType, Collectors.counting()));


        log.debug("📊 알림 통계 조회 완료: 총 {}개, 활성 {}개", totalAlerts, activeAlerts);
        return AlertStatisticsResponseDTO.from(totalAlerts,activeAlerts,todayAlertsCount,severityDistribution,typeDistribution);


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

    /**
     * 여러 알림 일괄 해결
     */
    @Transactional
    public int resolveMultipleAlerts(List<Long> alertIds, String resolvedBy) {

        int resolvedCount = 0;

        for (Long alertId : alertIds) {
            if (resolveAlert(alertId, resolvedBy)) {
                resolvedCount++;
            }
        }

        log.info("일괄 해결 완료: {}개 알림 by {}", resolvedCount, resolvedBy);
        return resolvedCount;
    }
}
