package org.example.packetanomalydetection.repository;

import org.example.packetanomalydetection.entity.Alert;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.example.packetanomalydetection.repository.projection.AlertStatisticsProjection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {


    /**
     * 해결되지 않은 알림 조회
     */
    @Query("SELECT a FROM Alert a WHERE a.resolved =false ORDER BY a.timestamp DESC")
    List<Alert> findByResolvedFalseOrderByTimestampDesc();

    /**
     * 특정 심각도의 알림 조회
     */
    @Query("SELECT a FROM Alert a WHERE a.severity =:severity ORDER BY a.timestamp DESC")
    List<Alert> findBySeverityOrderByTimestampDesc(AlertSeverity severity);

    /**
     * 특정 시간 범위의 알림 조회
     */
    @Query("SELECT a FROM Alert a WHERE a.timestamp BETWEEN :start AND :end AND a.resolved=false ORDER BY a.timestamp DESC")
    List<Alert> findByTimestampBetweenOrderByTimestampDesc(@Param("start") LocalDateTime start,
                                                           @Param("end") LocalDateTime end);


    /**
     * 특정 IP 관련 알림 조회
     */
    @Query("SELECT a FROM Alert a WHERE a.sourceIp =:sourceIp OR a.destIp =:destIp ORDER BY timestamp DESC")
    List<Alert> findBySourceIpOrDestIpOrderByTimestampDesc(@Param("sourceIp") String sourceIp,
                                                           @Param("destIp") String destIp);

    /**
     * 최근 알림 50개 조회
     */
    @Query("SELECT a FROM Alert a ORDER BY timestamp DESC LIMIT 50")
    List<Alert> findTop50ByOrderByTimestampDesc();

    /**
     * 활성 알림 수 조회
     */
    @Query("SELECT COUNT(a) FROM Alert a WHERE a.resolved = false")
    Long countActiveAlerts();


    @Query(" SELECT a FROM Alert a WHERE a.severity =:severity AND a.timestamp < timestamp")
    List<Alert> findBySeverityAndTimestampBefore(AlertSeverity severity, LocalDateTime timestamp);


    @Query("SELECT a FROM Alert a WHERE a.resolved = true AND a.timestamp < timestamp ")
    List<Alert> findByResolvedTrueAndTimestampBefore(LocalDateTime timestamp);

//    /**
//     * 심각도별 알림 통계
//     */
//    @Query("SELECT a.severity, COUNT(a) FROM Alert a " +
//            "WHERE a.timestamp >= :since " +
//            "GROUP BY a.severity")
//    List<Object[]> getSeverityStats(@Param("since") LocalDateTime since);
//
//    /**
//     * 알림 타입별 통계
//     */
//    @Query("SELECT a.alertType, COUNT(a) FROM Alert a " +
//            "WHERE a.timestamp >= :since " +
//            "GROUP BY a.alertType")
//    List<Object[]> getAlertTypeStats(@Param("since") LocalDateTime since);

    /**
     * GROUP BY 로 집계 처리로 AlertType 의 위험도 반환
     */
    @Query(value = """
        SELECT
            COUNT(*) as total_alerts,
            SUM(CASE WHEN a.resolved = 0 THEN 1 ELSE 0 END) as active_alerts,
            SUM(CASE WHEN a.severity = 'LOW' THEN 1 ELSE 0 END) as low_count,
            SUM(CASE WHEN a.severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
            SUM(CASE WHEN a.severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
            SUM(CASE WHEN a.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count
        FROM alert a
        WHERE timestamp BETWEEN :startTime AND :endTime
        """, nativeQuery = true)
   List <AlertStatisticsProjection> findAlertStatisticsByBetweenTime(@Param("startTime") LocalDateTime startTime,
                                                                    @Param("endTime") LocalDateTime endTime);

    /**
     * GROUP BY 로 알람 타입별로 AlertType 과 갯수를 반환
     */
    @Query(value = """
        SELECT a.alert_type, COUNT(*) as count
        FROM alert a
        WHERE timestamp BETWEEN :startTime AND :endTime
        GROUP BY a.alert_type
        """, nativeQuery = true)
    List<Object[]> findAlertTypeDistribution(
            @Param("startTime") LocalDateTime startTime,
            @Param("endTime") LocalDateTime endTime
    );
}
