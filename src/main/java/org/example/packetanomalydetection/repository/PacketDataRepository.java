package org.example.packetanomalydetection.repository;

import org.example.packetanomalydetection.entity.PacketData;
import org.example.packetanomalydetection.repository.projection.ActiveSourceIpProtocolProjection;
import org.example.packetanomalydetection.repository.projection.HourlyPacketCountProjection;
import org.example.packetanomalydetection.repository.projection.SuspiciousActivityProjection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

public interface PacketDataRepository extends JpaRepository<PacketData, Long> {

    List<PacketData> findByTimestampBetween(LocalDateTime start, LocalDateTime end);


    @Query("select p from PacketData p where p.sourceIp =: srcport order by p.timestamp desc")
    List<PacketData> findPacketBySrcPort(int srcPort);



    /**
     * 활발한 소스 IP 조회
     */
    @Query("SELECT DATE(p.timestamp) as date ,p.sourceIp, p.protocol, COUNT(p) as cnt " +
            "FROM PacketData p " +
            "WHERE DATE(p.timestamp)=:date " +
            "GROUP BY p.sourceIp, p.protocol " +
            "ORDER BY cnt DESC " +
            "LIMIT 50")
    List<ActiveSourceIpProtocolProjection> findActiveSourceIpsAndProtocols(@Param("date") LocalDate date);

    /**
     * 프로토콜별 통계
     */
    @Query("SELECT p.protocol, COUNT(p) FROM PacketData p " +
            "WHERE p.timestamp >= :since " +
            "GROUP BY p.protocol")
    List<Object[]> getProtocolStats(@Param("since") LocalDateTime since);



    @Query("SELECT DATE(p.timestamp) as date , HOUR(p.timestamp) as hour, COUNT(p) as count " +
            "FROM PacketData p " +
            "WHERE p.timestamp BETWEEN :start AND :end " +
            "GROUP BY HOUR(p.timestamp) " +
            "ORDER BY HOUR(p.timestamp)")
    List<HourlyPacketCountProjection> findHourlyPacketDistributionProjection(
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end);


    /**
     * 의심스러운 소스 IP + 프로토콜 조합 탐지
     * (같은 IP 에서 여러 프로토콜을 동시에 많이 사용하는 경우)
     */
    @Query("SELECT DATE(p.timestamp) as date ,p.sourceIp, p.protocol, COUNT(p) as cnt, " +
            "AVG(p.packetSize) as avgPacketSize " +
            "FROM PacketData p " +
            "WHERE DATE(p.timestamp) = :date " +
            "GROUP BY p.sourceIp, p.protocol " +
            "HAVING COUNT(p) > :threshold " +
            "ORDER BY cnt DESC "+
            "LIMIT 100")
    List<SuspiciousActivityProjection> findSuspiciousSourceIpProtocolActivity(
            @Param("date") LocalDate date,
            @Param("threshold") Long threshold
    );

//Test
//    @Query("SELECT new org.example.packetanomalydetection.dto.packetData.HourlyPacketCountResponseDTO(HOUR(p.timestamp), COUNT(p)) " +
//            "FROM PacketData p " +
//            "WHERE p.timestamp BETWEEN :start AND :end " +
//            "GROUP BY HOUR(p.timestamp) " +
//            "ORDER BY HOUR(p.timestamp)")
//    List<HourlyPacketCountResponseDTO> findHourlyPacketDistributionDTO(
//            @Param("start") LocalDateTime start,
//            @Param("end") LocalDateTime end);


   //Test
//    @Query("SELECT HOUR(p.timestamp) as hour, COUNT(p) as count " +
//            "FROM PacketData p " +
//            "WHERE p.timestamp BETWEEN :startTime AND :endTime " +
//            "GROUP BY HOUR(p.timestamp) " +
//            "ORDER BY HOUR(p.timestamp)")
//    List<Object[]> findHourlyPacketDistribution(@Param("startTime") LocalDateTime startTime,
//                                                @Param("endTime") LocalDateTime endTime);



}
