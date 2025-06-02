package org.example.packetanomalydetection.repository;

import org.example.packetanomalydetection.entity.Alert;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {
    /**
     * 해결되지 않은 알림 조회
     */
    @Query("SELECT a FROM Alert a WHERE a.resolved = false ORDER BY timestamp DESC")
    List<Alert> findByResolvedFalseOrderByTimestampDesc();

    /**
     * 특정 심각도의 알림 조회
     */
    @Query("SELECT a FROM Alert a WHERE a.severity =:severity ORDER BY timestamp DESC")
    List<Alert> findBySeverityOrderByTimestampDesc(AlertSeverity severity);

    /**
     * 특정 시간 범위의 알림 조회
     */
    @Query("SELECT a FROM Alert a WHERE a.timestamp BETWEEN :start AND :end ORDER BY a.timestamp DESC")
    List<Alert> findByTimestampBetweenOrderByTimestampDesc(@Param("start") LocalDateTime start,
                                                           @Param("end") LocalDateTime end);

    /**
     * 특정 IP 관련 알림 조회
     */
    @Query("SELECT a FROM Alert a WHERE a.sourceIp =:sourceIp OR a.destIp =: destIp ORDER BY timestamp DESC")
    List<Alert> findBySourceIpOrDestIpOrderByTimestampDesc(String sourceIp, String destIp);

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

    /**
     * 특정 시간 이후의 알림 수 조회
     */
    @Query("SELECT COUNT(a) FROM Alert a WHERE a.timestamp >= :since")
    Long countAlertsSince(@Param("since") LocalDateTime since);


    @Query(" SELECT a FROM Alert a WHERE a.severity =:severity AND a.timestamp < timestamp")
    List<Alert> findBySeverityAndTimestampBefore(AlertSeverity severity, LocalDateTime timestamp);


    @Query("SELECT a FROM Alert a WHERE a.resolved = true AND a.timestamp < timestamp ")
    List<Alert> findByResolvedTrueAndTimestampBefore(LocalDateTime timestamp);

    /**
     * 심각도별 알림 통계
     */
    @Query("SELECT a.severity, COUNT(a) FROM Alert a " +
            "WHERE a.timestamp >= :since " +
            "GROUP BY a.severity")
    List<Object[]> getSeverityStats(@Param("since") LocalDateTime since);

    /**
     * 알림 타입별 통계
     */
    @Query("SELECT a.alertType, COUNT(a) FROM Alert a " +
            "WHERE a.timestamp >= :since " +
            "GROUP BY a.alertType")
    List<Object[]> getAlertTypeStats(@Param("since") LocalDateTime since);
}
