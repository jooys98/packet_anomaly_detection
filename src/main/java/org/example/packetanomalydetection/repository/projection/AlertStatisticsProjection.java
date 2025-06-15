package org.example.packetanomalydetection.repository.projection;

import java.math.BigDecimal;

public interface AlertStatisticsProjection {
    //Statistics 통계값을 담을 인터페이스

        Long getTotalAlerts(); // COUNT(*) 결과는 Long 으로 매핑
        BigDecimal getActiveAlerts(); // SUM() 결과타입인 BigDecimal 로 매핑
        BigDecimal getLowCount();
        BigDecimal getMediumCount();
        BigDecimal getHighCount();
        BigDecimal getCriticalCount();

      //BigDecimal -> Long 타입 변환
        default Long getActiveAlertsAsLong() {
            return getActiveAlerts() != null ? getActiveAlerts().longValue() : 0L;
        }
        default Long getLowCountAsLong() {
            return getLowCount() != null ? getLowCount().longValue() : 0L;
        }

        default Long getMediumCountAsLong() {
            return getMediumCount() != null ? getMediumCount().longValue() : 0L;
        }
        default Long getHighCountAsLong() {
            return getHighCount() != null ? getHighCount().longValue() : 0L;
        }
        default Long getCriticalCountAsLong() {
            return getCriticalCount() != null ? getCriticalCount().longValue() : 0L;
        }
}
