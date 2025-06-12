package org.example.packetanomalydetection.repository;

import org.example.packetanomalydetection.entity.CaptureStatistics;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface CaptureStatisticsRepository extends JpaRepository<CaptureStatistics, Long> {

    @Query("SELECT cs FROM CaptureStatistics cs WHERE cs.captureStartTime >= :startTime AND cs.captureStartTime < :endTime ORDER BY cs.captureStartTime DESC")
    List<CaptureStatistics> findByDateRange(@Param("startTime") LocalDateTime startTime, @Param("endTime") LocalDateTime endTime);

    // ✅ 날짜별 통계 집계 쿼리 (추가 기능)
    // 최근 통계 조회
    @Query("SELECT cs FROM CaptureStatistics cs WHERE cs.captureStartTime = :daily ORDER BY cs.captureStartTime DESC")
    List<CaptureStatistics> findRecentStatistics(@Param("daily") LocalDateTime daily);



}
