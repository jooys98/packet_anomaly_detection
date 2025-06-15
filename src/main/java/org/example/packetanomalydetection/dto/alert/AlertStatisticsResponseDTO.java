package org.example.packetanomalydetection.dto.alert;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.example.packetanomalydetection.entity.constants.AlertType;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.example.packetanomalydetection.repository.projection.AlertStatisticsProjection;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AlertStatisticsResponseDTO {


    private Long activeAlerts;
    private Long totalAlerts; // 오늘의 알림 수
    private SeverityDistribution severityDistribution;
    private Map<String, Long> typeDistribution;
    private Map<String, String> typeDescriptions;
    private Map<String, AlertSeverity> typeDefaultSeverities;
    private LocalDateTime generatedAt;


    public static AlertStatisticsResponseDTO fromQueryResults(
            AlertStatisticsProjection basicStats,
            List<Object[]> typeDistribution) {

        Long totalAlerts = basicStats.getTotalAlerts();
        Long activeAlerts = basicStats.getActiveAlertsAsLong();

        SeverityDistribution severityDist = SeverityDistribution.builder()
                .low(basicStats.getLowCountAsLong())
                .medium(basicStats.getMediumCountAsLong())
                .high(basicStats.getHighCountAsLong())
                .critical(basicStats.getCriticalCountAsLong())
                .build();


        Long severityTotal = severityDist.getTotal();
        if (!totalAlerts.equals(severityTotal)) {
            throw new IllegalArgumentException("Total alerts mismatch");
        }

        //  AlertType 클래스 활용한 타입별 통계 처리
        Map<String, Long> typeStats = new LinkedHashMap<>();
        Map<String, String> typeDescs = new LinkedHashMap<>();
        Map<String, AlertSeverity> typeSeverities = new LinkedHashMap<>();

        for (Object[] row : typeDistribution) {
            String alertType = (String) row[0];
            Long count = ((Long) row[1]);

            if (count > 0) {  // 실제 발생한 알림만 포함
                typeStats.put(alertType, count);
                typeDescs.put(alertType, AlertType.getKoreanDescription(alertType));
                typeSeverities.put(alertType, AlertType.getDefaultSeverity(alertType));
            }
        }
        return AlertStatisticsResponseDTO.builder()
                .activeAlerts(activeAlerts)
                .totalAlerts(severityTotal)
                .severityDistribution(severityDist)
                .typeDistribution(typeStats)
                .typeDescriptions(typeDescs)
                .typeDefaultSeverities(typeSeverities)
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


    }


}
