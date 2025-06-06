package org.example.packetanomalydetection.util.tracker;


import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 *  TrafficTracker - 트래픽 추적기
 *
 * 역할: 특정 시간대의 트래픽 양과 패턴을 추적해서 DDoS 공격 탐지
 *
 * 추적 요소:
 * 1. 시간당 패킷 수
 * 2. 고유 소스 IP 수
 * 3. 프로토콜 분포
 * 4. 평균 패킷 크기
 */
@Getter
@Slf4j
public class TrafficTracker {

    //  패킷 수 카운터
    private int packetCount = 0;

    //  고유 소스 IP 집합
    private final Set<String> sourceIps = ConcurrentHashMap.newKeySet();

    // 프로토콜별 패킷 수
    private final Map<String, Integer> protocolCounts = new ConcurrentHashMap<>();

    //  패킷 크기 통계
    private final List<Integer> packetSizes = new ArrayList<>();

    // 추적 시작 시간
    private final LocalDateTime startTime = LocalDateTime.now();

    /**
     *  DDoS 공격 의심 여부 판단
     */
    public synchronized boolean isDdosSuspicious() {

        //  판단 기준들
        boolean highPacketRate = getPacketsPerSecond() > 1000;  // 초당 1000개 이상
        boolean manySourceIps = getUniqueSourceIpCount() > 100; // 100개 이상 IP
        boolean shortDuration = java.time.Duration.between(startTime, LocalDateTime.now()).getSeconds() < 60; // 1분 이내

        //  프로토콜 집중도 (하나의 프로토콜이 80% 이상)
        Map<String, Double> distribution = getProtocolDistribution();
        boolean protocolConcentration = distribution.values().stream()
                .anyMatch(percentage -> percentage > 80);

        //  2개 이상 조건 만족 시 의심
        int suspiciousFactors = 0;
        if (highPacketRate) suspiciousFactors++;
        if (manySourceIps) suspiciousFactors++;
        if (shortDuration) suspiciousFactors++;
        if (protocolConcentration) suspiciousFactors++;

        boolean suspicious = suspiciousFactors >= 2;

        if (suspicious) {
            log.warn(" DDoS 공격 의심: PPS={}, IPs={}, 프로토콜 집중={}",
                    getPacketsPerSecond(), getUniqueSourceIpCount(), protocolConcentration);
        }

        return suspicious;
    }

    /**
     * 트래픽 요약 정보
     */
    public synchronized String getTrafficSummary() {
        return String.format(
                " 트래픽 요약: 패킷 %d개, IP %d개, PPS %.1f, 평균크기 %.1f bytes",
                packetCount, getUniqueSourceIpCount(),
                getPacketsPerSecond(), getAveragePacketSize()
        );
    }

    /**
     *  패킷 수 증가
     */
    public synchronized void incrementPacketCount() {
        packetCount++;
    }

    /**
     * 소스 IP 추가
     */
    public void addSourceIp(String sourceIp) {
        sourceIps.add(sourceIp);
    }

    /**
     *  프로토콜 카운트 증가
     */
    public synchronized void addProtocol(String protocol) {
        protocolCounts.merge(protocol, 1, Integer::sum);
    }

    /**
     * 패킷 크기 추가
     */
    public synchronized void addPacketSize(int size) {
        packetSizes.add(size);
    }

    /**
     *  고유 소스 IP 수
     */
    public int getUniqueSourceIpCount() {
        return sourceIps.size();
    }

    /**
     *  초당 패킷 수 계산
     */
    public synchronized double getPacketsPerSecond() {
        long durationSeconds = java.time.Duration.between(startTime, LocalDateTime.now()).getSeconds();
        if (durationSeconds == 0) return packetCount;
        return (double) packetCount / durationSeconds;
    }

    /**
     * 평균 패킷 크기
     */
    public synchronized double getAveragePacketSize() {
        if (packetSizes.isEmpty()) return 0;
        return packetSizes.stream()
                .mapToInt(Integer::intValue)
                .average()
                .orElse(0.0);
    }

    /**
     *  프로토콜 분포 분석
     */
    public synchronized Map<String, Double> getProtocolDistribution() {
        if (protocolCounts.isEmpty()) return new HashMap<>();

        int total = protocolCounts.values().stream()
                .mapToInt(Integer::intValue)
                .sum();

        Map<String, Double> distribution = new HashMap<>();
        protocolCounts.forEach((protocol, count) ->
                distribution.put(protocol, (double) count / total * 100)
        );

        return distribution;
    }




}