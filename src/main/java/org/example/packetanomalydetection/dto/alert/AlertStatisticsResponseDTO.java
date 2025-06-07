package org.example.packetanomalydetection.dto.alert;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;

import java.time.LocalDateTime;
import java.util.Map;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AlertStatisticsResponseDTO {

    //전체 알림 수
    private Long totalAlerts;
    private Long activeAlerts;
    private Long todayAlerts;
    private Long totalCreatedSinceStart;
    private SeverityDistribution severityDistribution;
    private Map<String, Long> typeDistribution;
    private LocalDateTime generatedAt;



    public static AlertStatisticsResponseDTO from(long totalAlerts, long activeAlerts, long todayAlertsCount, SeverityDistribution severityDistribution, Map<String, Long> typeDistribution) {
        return  AlertStatisticsResponseDTO.builder()
                .totalAlerts(totalAlerts)
                .activeAlerts(activeAlerts)
                .todayAlerts(todayAlertsCount)
                .severityDistribution(severityDistribution)
                .typeDistribution(typeDistribution)
                .generatedAt(LocalDateTime.now())
                .build();
    }

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    //위험도 분포를 표기하기 위한 정적 서브 클래스
    public static class SeverityDistribution {

        private Long low;

        private Long medium;

        private Long high;

        private Long critical;

        public static SeverityDistribution from(Map<AlertSeverity, Long> severityStats) {
            return AlertStatisticsResponseDTO.SeverityDistribution.builder()
                    .low(severityStats.getOrDefault(AlertSeverity.LOW, 0L))
                    .medium(severityStats.getOrDefault(AlertSeverity.MEDIUM, 0L))
                    .high(severityStats.getOrDefault(AlertSeverity.HIGH, 0L))
                    .critical(severityStats.getOrDefault(AlertSeverity.CRITICAL, 0L))
                    .build();
        }

        /**
         * 전체 심각도별 알림 수
         */
        public Long getTotal() {
            return (low != null ? low : 0) +
                    (medium != null ? medium : 0) +
                    (high != null ? high : 0) +
                    (critical != null ? critical : 0);
        }

        /**
         * 높은 우선순위 알림 수 (HIGH + CRITICAL)
         */
        public Long getHighPriorityCount() {
            return (high != null ? high : 0) + (critical != null ? critical : 0);
        }

        /**
         * 가장 많은 심각도 반환
         */
        public AlertSeverity getMostFrequentSeverity() {
            long maxCount = Math.max(Math.max(low != null ? low : 0, medium != null ? medium : 0),
                    Math.max(high != null ? high : 0, critical != null ? critical : 0));

            if (critical != null && critical == maxCount) return AlertSeverity.CRITICAL;
            if (high != null && high == maxCount) return AlertSeverity.HIGH;
            if (medium != null && medium == maxCount) return AlertSeverity.MEDIUM;
            return AlertSeverity.LOW;
        }
    }


}
