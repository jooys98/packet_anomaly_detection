package org.example.packetanomalydetection.repository;

import org.example.packetanomalydetection.entity.PacketData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface PacketDataRepository extends JpaRepository<PacketData, Long> {
    /**
     * 특정 시간 범위의 패킷 조회
     */
    List<PacketData> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

    /**
     * 특정 IP의 패킷 조회
     */
    List<PacketData> findBySourceIpOrDestIp(String sourceIp, String destIp);

    /**
     * 최근 패킷 조회
     */
    List<PacketData> findTop100ByOrderByTimestampDesc();

    /**
     * 특정 시간 이후의 패킷 수 조회
     */
    @Query("SELECT COUNT(p) FROM PacketData p WHERE p.timestamp >= :since")
    Long countPacketsSince(@Param("since") LocalDateTime since);

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
