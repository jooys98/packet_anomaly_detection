package org.example.packetanomalydetection.repository;

import org.example.packetanomalydetection.entity.PacketData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface PacketDataRepository extends JpaRepository<PacketData, Long> {

    List<PacketData> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

    /**
     * 특정 날짜 범위의 패킷 개수 조회
     */
    @Query("SELECT COUNT(p) FROM PacketData p WHERE p.timestamp BETWEEN :startTime AND :endTime")
    Long countPacketsByDateRange(@Param("startTime") LocalDateTime startTime,
                                 @Param("endTime") LocalDateTime endTime);

    /**
     * 특정 날짜 범위의 첫 번째 패킷 시간
     */
    @Query("SELECT MIN(p.timestamp) FROM PacketData p WHERE p.timestamp BETWEEN :startTime AND :endTime")
    LocalDateTime findFirstPacketTimeByDateRange(@Param("startTime") LocalDateTime startTime,
                                                 @Param("endTime") LocalDateTime endTime);

    /**
     * 특정 날짜 범위의 마지막 패킷 시간
     */
    @Query("SELECT MAX(p.timestamp) FROM PacketData p WHERE p.timestamp BETWEEN :startTime AND :endTime")
    LocalDateTime findLastPacketTimeByDateRange(@Param("startTime") LocalDateTime startTime,
                                                @Param("endTime") LocalDateTime endTime);

//    /**
//     * 특정 날짜의 시간별 패킷 개수 분포
//     */
//    @Query("SELECT HOUR(p.timestamp) as hour, COUNT(p) as count " +
//            "FROM PacketData p " +
//            "WHERE p.timestamp BETWEEN :startTime AND :endTime " +
//            "GROUP BY HOUR(p.timestamp) " +
//            "ORDER BY hour")
//    List<Object[]> findHourlyPacketDistribution(@Param("startTime") LocalDateTime startTime,
//                                                @Param("endTime") LocalDateTime endTime);

    /**
     * 특정 날짜 범위의 모든 패킷 (PPS 계산용)
     */
    @Query("SELECT p.timestamp FROM PacketData p " +
            "WHERE p.timestamp BETWEEN :startTime AND :endTime " +
            "ORDER BY p.timestamp")
    List<LocalDateTime> findPacketTimestampsByDateRange(@Param("startTime") LocalDateTime startTime,
                                                        @Param("endTime") LocalDateTime endTime);

    /**
     * 특정 IP의 패킷 조회
     */
    List<PacketData> findBySourceIpOrDestIp(String sourceIp, String destIp);

    /**
     * 최근 패킷 조회
     */
    List<PacketData> findTop100ByOrderByTimestampDesc();


    /**
     * 가장 활발한 소스 IP 조회
     */
    @Query("SELECT p.sourceIp, COUNT(p) as cnt FROM PacketData p " +
            "WHERE p.timestamp >= :since " +
            "GROUP BY p.sourceIp " +
            "ORDER BY cnt DESC")
    List<Object[]> findMostActiveSourceIps(@Param("since") LocalDateTime since);

    /**
     * 특정 IP의 최근 연결 시도 횟수
     */
    @Query("SELECT COUNT(p) FROM PacketData p " +
            "WHERE p.sourceIp = :ip AND p.timestamp >= :since")
    Long countConnectionAttempts(@Param("ip") String ip, @Param("since") LocalDateTime since);

    /**
     * 프로토콜별 통계
     */
    @Query("SELECT p.protocol, COUNT(p) FROM PacketData p " +
            "WHERE p.timestamp >= :since " +
            "GROUP BY p.protocol")
    List<Object[]> getProtocolStats(@Param("since") LocalDateTime since);
}
