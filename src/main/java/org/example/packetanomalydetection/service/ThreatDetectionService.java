package org.example.packetanomalydetection.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.config.DetectionConfig;
import org.example.packetanomalydetection.entity.Alert;
import org.example.packetanomalydetection.entity.PacketData;
import org.example.packetanomalydetection.entity.constants.AlertType;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.example.packetanomalydetection.repository.AlertRepository;
import org.example.packetanomalydetection.repository.PacketDataRepository;
import org.example.packetanomalydetection.util.tracker.ConnectionAttemptTracker;
import org.example.packetanomalydetection.util.tracker.PortScanTracker;
import org.example.packetanomalydetection.util.tracker.TrafficTracker;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 🛡️ ThreatDetectionService - 위협 탐지 핵심 서비스
 *
 * 🎯 주요 기능:
 * 1. 실시간 패킷 분석 - 패킷이 캡처될 때마다 즉시 분석
 * 2. 주기적 패턴 분석 - 일정 시간 간격으로 누적 데이터 분석
 * 3. 다양한 공격 패턴 탐지 - 포트 스캔, DDoS, 브루트포스 등
 * 4. 알림 생성 및 관리 - 위협 발견 시 Alert 생성
 *
 * 🔍 탐지 방식:
 * - 규칙 기반 탐지 (Rule-based Detection)
 * - 통계적 이상 탐지 (Statistical Anomaly Detection)
 * - 패턴 매칭 (Pattern Matching)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ThreatDetectionService {

    private final DetectionConfig detectionConfig;
    private final PacketDataRepository packetRepository;
    private final AlertRepository alertRepository;
    private final AlertService alertService;

    // 📊 실시간 통계 추적용 메모리 캐시
    // IP별 연결 시도 횟수 추적 (메모리에서 빠른 접근)
    private final Map<String, ConnectionAttemptTracker> connectionAttempts = new ConcurrentHashMap<>();

    // 포트 스캔 추적 (IP별로 어떤 포트들에 접근했는지)
    private final Map<String, PortScanTracker> portScanAttempts = new ConcurrentHashMap<>();

    // 트래픽 급증 탐지용 (시간대별 패킷 수)
    private final Map<String, TrafficTracker> trafficStats = new ConcurrentHashMap<>();

    /**
     * 🚨 실시간 패킷 분석 - 가장 중요한 메서드!
     *
     * PacketCaptureService에서 패킷이 캡처될 때마다 호출됨
     * 빠른 응답이 필요하므로 간단하고 효율적인 검사만 수행
     */
    public void analyzePacketRealtime(PacketData packet) {

        if (!detectionConfig.getEnableAutoDetection()) {
            return; // 자동 탐지 비활성화 상태
        }

        try {
            log.debug("🔍 실시간 패킷 분석: {}:{} → {}:{}",
                    packet.getSourceIp(), packet.getSourcePort(),
                    packet.getDestIp(), packet.getDestPort());

            // ⚡ 빠른 실시간 검사들 (즉시 탐지 가능한 것들)

            // 1.  대용량 패킷 탐지 (즉시 판단 가능)
            checkLargePacket(packet);

            // 2. 의심스러운 포트 접근 탐지
            checkSuspiciousPortAccess(packet);

            // 3. 연결 시도 횟수 업데이트 및 체크
            updateConnectionAttempts(packet);

            // 4. 포트 스캔 패턴 업데이트 및 체크
            updatePortScanTracking(packet);

            // 5.  트래픽 통계 업데이트
            updateTrafficStats(packet);

        } catch (Exception e) {
            log.error(" 실시간 패킷 분석 중 오류", e);
        }
    }

    /**
     *1. 대용량 패킷 탐지
     * 정상적인 패킷보다 비정상적으로 큰 패킷은 의심스러움
     * - 버퍼 오버플로우 공격 시도
     * - 데이터 유출 시도
     * - DDoS 공격의 일종
     */
    private void checkLargePacket(PacketData packet) {

        if (packet.getPacketSize() == null) return;

        int packetSize = packet.getPacketSize();
        int threshold = detectionConfig.getLargePacketThreshold();

        if (packetSize > threshold) {
            log.warn("📦 대용량 패킷 탐지: {} bytes (임계값: {} bytes)", packetSize, threshold);

            // 🚨 알림 생성
            Alert alert = Alert.builder()
                    .alertType(AlertType.LARGE_PACKET)
                    .description(String.format(
                            "비정상적으로 큰 패킷 탐지: %d bytes (정상 범위: %d bytes 이하)\n" +
                                    "출발지: %s:%s → 목적지: %s:%s",
                            packetSize, threshold,
                            packet.getSourceIp(), packet.getSourcePort(),
                            packet.getDestIp(), packet.getDestPort()
                    ))
                    .severity(AlertSeverity.MEDIUM)
                    .sourceIp(packet.getSourceIp())
                    .destIp(packet.getDestIp())
                    .affectedPort(packet.getDestPort())
                    .build();

            alertService.createAlert(alert);

            // 📱 즉시 출력
            System.out.println(" [대용량 패킷] " + packet.getSourceIp() + " → " +
                    packet.getDestIp() + " (" + packetSize + " bytes)");
        }
    }

    /**
     * 2. 의심스러운 포트 접근 탐지
     * 일반 사용자가 접근하기 어려운 포트들:
     * - 시스템 관리용 포트 (SSH, Telnet, RDP)
     * - 데이터베이스 포트 (MySQL, PostgreSQL)
     * - 잘 알려진 해킹 도구 포트
     */
    private void checkSuspiciousPortAccess(PacketData packet) {

        if (packet.getDestPort() == null) return;

        int destPort = packet.getDestPort();

        //의심스러운 포트 목록
        Set<Integer> suspiciousPorts = Set.of(
                22,    // SSH
                23,    // Telnet
                3389,  // RDP (원격 데스크톱)
                21,    // FTP
                135,   // RPC
                139,   // NetBIOS
                445,   // SMB
                1433,  // SQL Server
                3306,  // MySQL
                5432,  // PostgreSQL
                6379,  // Redis
                27017, // MongoDB
                9200   // Elasticsearch
        );

        if (suspiciousPorts.contains(destPort)) {
            log.info("🚪 의심스러운 포트 접근: {}:{} → {}:{}",
                    packet.getSourceIp(), packet.getSourcePort(),
                    packet.getDestIp(), destPort);

            // 🔍 같은 IP에서 여러 의심스러운 포트에 접근하는지 확인
            String sourceIp = packet.getSourceIp();
            PortScanTracker tracker = portScanAttempts.computeIfAbsent(
                    sourceIp, k -> new PortScanTracker()
            );

            tracker.addPortAccess(destPort, packet.getDestIp());

            // 📊 의심스러운 포트를 3개 이상 접근했으면 알림
            if (tracker.getSuspiciousPortCount() >= 3) {
                createSuspiciousConnectionAlert(packet, tracker);
            }
        }
    }

    /**
     * 📊 3. 연결 시도 횟수 추적 및 브루트포스 탐지
     *
     * 동일한 IP에서 짧은 시간에 많은 연결을 시도하는 것은:
     * - 브루트포스 공격 (무차별 대입 공격)
     * - 자동화된 스캔 도구 사용
     * - 봇넷 공격
     */
    private void updateConnectionAttempts(PacketData packet) {

        String sourceIp = packet.getSourceIp();

        // 🔄 연결 시도 추적기 가져오기 (없으면 새로 생성)
        ConnectionAttemptTracker tracker = connectionAttempts.computeIfAbsent(
                sourceIp, k -> new ConnectionAttemptTracker()
        );

        // 📈 연결 시도 추가
        tracker.addAttempt(packet);

        // ⏰ 설정된 시간 윈도우 내의 연결 시도 수 계산
        int timeWindowMinutes = detectionConfig.getTimeWindowMinutes();
        int attemptsInWindow = tracker.getAttemptsInLastMinutes(timeWindowMinutes);
        int threshold = detectionConfig.getConnectionAttemptThreshold();

        // 🚨 임계값 초과 시 브루트포스 공격으로 판단
        if (attemptsInWindow >= threshold) {
            log.warn("🔨 브루트포스 공격 탐지: {} ({}분간 {}회 연결 시도)",
                    sourceIp, timeWindowMinutes, attemptsInWindow);

            createBruteForceAlert(packet, attemptsInWindow, timeWindowMinutes);

            // 📊 추적기 리셋 (중복 알림 방지)
            tracker.reset();
        }
    }

    /**
     * 🎯 4. 포트 스캔 패턴 추적
     *
     * 포트 스캔의 특징:
     * - 동일한 IP에서 여러 포트에 연속적으로 접근
     * - 짧은 시간에 많은 포트 시도
     * - 대부분 연결 실패 (포트가 닫혀있음)
     */
    private void updatePortScanTracking(PacketData packet) {

        String sourceIp = packet.getSourceIp();

        PortScanTracker tracker = portScanAttempts.computeIfAbsent(
                sourceIp, k -> new PortScanTracker()
        );

        // 🎯 포트 접근 기록 추가
        if (packet.getDestPort() != null) {
            tracker.addPortAccess(packet.getDestPort(), packet.getDestIp());
        }

        // 📊 포트 스캔 임계값 체크
        int uniquePortCount = tracker.getUniquePortCount();
        int threshold = detectionConfig.getPortScanThreshold();

        if (uniquePortCount >= threshold) {
            log.warn("🔍 포트 스캔 탐지: {} ({}개 포트 스캔)", sourceIp, uniquePortCount);

            createPortScanAlert(packet, tracker);

            // 📊 추적기 리셋
            tracker.reset();
        }
    }

    /**
     * 📈 5. 트래픽 통계 업데이트 및 급증 탐지
     *
     * 트래픽 급증의 원인:
     * - DDoS 공격
     * - 바이러스/웜 확산
     * - 자동화된 봇 활동
     */
    private void updateTrafficStats(PacketData packet) {

        // 🕐 현재 분(minute) 단위로 트래픽 집계
        String currentMinute = LocalDateTime.now().toString().substring(0, 16); // YYYY-MM-DDTHH:mm

        TrafficTracker tracker = trafficStats.computeIfAbsent(
                currentMinute, k -> new TrafficTracker()
        );

        tracker.incrementPacketCount();
        tracker.addSourceIp(packet.getSourceIp());

        // 📊 1분간 패킷 수가 임계값 초과 시 알림
        int packetCount = tracker.getPacketCount();
        int threshold = detectionConfig.getTrafficSpikeThreshold();

        if (packetCount >= threshold) {
            log.warn("📈 트래픽 급증 탐지: {}분에 {}개 패킷 (임계값: {})",
                    currentMinute, packetCount, threshold);

            createTrafficSpikeAlert(currentMinute, tracker);
        }
    }


    /**
     * 브루트포스 공격 알림 생성
     */
    private void createBruteForceAlert(PacketData packet, int attemptCount, int timeWindow) {
        Alert alert = Alert.builder()
                .alertType(AlertType.MULTIPLE_FAILED_ATTEMPTS)
                .description(String.format(
                        "브루트포스 공격 탐지\n" +
                                "공격자 IP: %s\n" +
                                "연결 시도: %d회 (%d분간)\n" +
                                "대상: %s:%s",
                        packet.getSourceIp(), attemptCount, timeWindow,
                        packet.getDestIp(), packet.getDestPort()
                ))
                .severity(AlertSeverity.HIGH)
                .sourceIp(packet.getSourceIp())
                .destIp(packet.getDestIp())
                .affectedPort(packet.getDestPort())
                .build();

        alertService.createAlert(alert);

        System.out.println(" [브루트포스] " + packet.getSourceIp() +
                " → " + attemptCount + "회 연결 시도");
    }

    /**
     * 🔍 포트 스캔 알림 생성
     */
    private void createPortScanAlert(PacketData packet, PortScanTracker tracker) {
        Alert alert = Alert.builder()
                .alertType(AlertType.PORT_SCAN)
                .description(String.format(
                        "포트 스캔 공격 탐지\n" +
                                "공격자 IP: %s\n" +
                                "스캔된 포트 수: %d개\n" +
                                "스캔된 포트: %s\n" +
                                "대상 서버: %s",
                        packet.getSourceIp(),
                        tracker.getUniquePortCount(),
                        tracker.getScannedPorts().toString(),
                        packet.getDestIp()
                ))
                .severity(AlertSeverity.HIGH)
                .sourceIp(packet.getSourceIp())
                .destIp(packet.getDestIp())
                .build();

        alertService.createAlert(alert);

        System.out.println("[포트 스캔] " + packet.getSourceIp() +
                " → " + tracker.getUniquePortCount() + "개 포트");
    }

    /**
     * 의심스러운 연결 알림 생성
     */
    private void createSuspiciousConnectionAlert(PacketData packet, PortScanTracker tracker) {
        Alert alert = Alert.builder()
                .alertType(AlertType.SUSPICIOUS_CONNECTION)
                .description(String.format(
                        "의심스러운 포트 접근 탐지\n" +
                                "접근자 IP: %s\n" +
                                "의심스러운 포트 접근: %d개\n" +
                                "최근 접근 포트: %s",
                        packet.getSourceIp(),
                        tracker.getSuspiciousPortCount(),
                        tracker.getScannedPorts().toString()
                ))
                .severity(AlertSeverity.MEDIUM)
                .sourceIp(packet.getSourceIp())
                .destIp(packet.getDestIp())
                .affectedPort(packet.getDestPort())
                .build();

        alertService.createAlert(alert);

        System.out.println(" [의심스러운 접근] " + packet.getSourceIp() +
                " → 시스템 포트 " + packet.getDestPort());
    }

    /**
     * 📈 트래픽 급증 알림 생성
     */
    private void createTrafficSpikeAlert(String timeWindow, TrafficTracker tracker) {
        Alert alert = Alert.builder()
                .alertType(AlertType.TRAFFIC_SPIKE)
                .description(String.format(
                        "네트워크 트래픽 급증 탐지\n" +
                                "시간: %s\n" +
                                "패킷 수: %d개\n" +
                                "고유 소스 IP: %d개\n" +
                                "평균 대비 증가율: 예상치 초과",
                        timeWindow,
                        tracker.getPacketCount(),
                        tracker.getUniqueSourceIpCount()
                ))
                .severity(AlertSeverity.CRITICAL)
                .build();

        alertService.createAlert(alert);

        System.out.println(" [트래픽 급증] " + timeWindow +
                " → " + tracker.getPacketCount() + "개 패킷");
    }


    /**
     * 🕐 주기적 종합 분석 (5분마다)
     *
     * 실시간으로는 탐지하기 어려운 복잡한 패턴들을 분석
     * - 시간대별 트래픽 패턴 변화
     * - IP별 장기간 행동 패턴
     * - 네트워크 전체의 이상 징후
     */
    @Scheduled(fixedRate = 300000) // 5분마다 실행
    public void performPeriodicAnalysis() {

        if (!detectionConfig.getEnableAutoDetection()) {
            return;
        }

        try {
            log.info(" 주기적 위협 분석 시작...");

            // 🕐 분석 시간 범위 설정 (최근 5분)
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime fiveMinutesAgo = now.minusMinutes(5);

            // 📊 최근 5분간의 패킷 데이터 조회
            List<PacketData> recentPackets = packetRepository.findByTimestampBetween(
                    fiveMinutesAgo, now
            );

            log.info(" 분석 대상: {}개 패킷 ({}~{})",
                    recentPackets.size(), fiveMinutesAgo, now);

            //  복합 패턴 분석들
            analyzeNetworkBehaviorPatterns(recentPackets);
            analyzeProtocolDistribution(recentPackets);
            analyzeGeographicalPatterns(recentPackets);

            //  오래된 추적 데이터 정리
            cleanupOldTrackingData();

            log.info("주기적 위협 분석 완료");

        } catch (Exception e) {
            log.error(" 주기적 분석 중 오류", e);
        }
    }

    /**
     *  네트워크 행동 패턴 분석
     */
    private void analyzeNetworkBehaviorPatterns(List<PacketData> packets) {

        //  IP별 패킷 수 집계
        Map<String, Long> ipPacketCounts = packets.stream()
                .collect(Collectors.groupingBy(
                        PacketData::getSourceIp,
                        Collectors.counting()
                ));

        //  비정상적으로 활발한 IP 탐지
        long averagePacketsPerIp = ipPacketCounts.values().stream()
                .mapToLong(Long::longValue)
                .sum() / Math.max(1, ipPacketCounts.size());

        ipPacketCounts.entrySet().stream()
                .filter(entry -> entry.getValue() > averagePacketsPerIp * 10) // 평균의 10배 이상
                .forEach(entry -> {
                    log.warn(" 비정상적 활발한 IP: {} ({}개 패킷, 평균: {})",
                            entry.getKey(), entry.getValue(), averagePacketsPerIp);

                    // 필요시 알림 생성
                    createSuspiciousActivityAlert(entry.getKey(), entry.getValue());
                });
    }

    /**
     *  프로토콜 분포 분석
     */
    private void analyzeProtocolDistribution(List<PacketData> packets) {

        Map<String, Long> protocolCounts = packets.stream()
                .collect(Collectors.groupingBy(
                        PacketData::getProtocol,
                        Collectors.counting()
                ));

        log.info(" 프로토콜 분포: {}", protocolCounts);

        //  비정상적인 프로토콜 분포 탐지
        // 예: ICMP가 전체의 50% 이상이면 ICMP 플러드 공격 의심
        long totalPackets = packets.size();
        protocolCounts.entrySet().stream()
                .filter(entry -> "ICMP".equals(entry.getKey()))
                .filter(entry -> entry.getValue() > totalPackets * 0.5)
                .forEach(entry -> {
                    log.warn(" ICMP 플러드 의심: {}개 패킷 (전체의 {}%)",
                            entry.getValue(),
                            (entry.getValue() * 100 / totalPackets));
                });
    }

    /**
     *  지리적 패턴 분석 (간단한 예시)
     */
    private void analyzeGeographicalPatterns(List<PacketData> packets) {

        //  외부 IP 주소들 추출 (사설 IP가 아닌 것들)
        Set<String> externalIps = packets.stream()
                .map(PacketData::getSourceIp)
                .filter(ip -> !isPrivateIp(ip))
                .collect(Collectors.toSet());

        if (externalIps.size() > 20) {
            log.warn("🌍 다수의 외부 IP 탐지: {}개 (DDoS 공격 의심)", externalIps.size());
        }
    }

    /**
     *  오래된 추적 데이터 정리 (메모리 관리)
     */
    private void cleanupOldTrackingData() {

        // 🕐 1시간 이상 된 데이터 정리
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);

        // 연결 시도 추적 데이터 정리
        connectionAttempts.entrySet().removeIf(entry ->
                entry.getValue().getLastActivity().isBefore(oneHourAgo)
        );

        // 포트 스캔 추적 데이터 정리
        portScanAttempts.entrySet().removeIf(entry ->
                entry.getValue().getLastActivity().isBefore(oneHourAgo)
        );

        // 트래픽 통계 정리 (10분 이상 된 데이터)
        LocalDateTime tenMinutesAgo = LocalDateTime.now().minusMinutes(10);
        trafficStats.entrySet().removeIf(entry -> {
            try {
                LocalDateTime entryTime = LocalDateTime.parse(entry.getKey() + ":00");
                return entryTime.isBefore(tenMinutesAgo);
            } catch (Exception e) {
                return true; // 파싱 실패한 것들은 삭제
            }
        });

        log.debug("🧹 추적 데이터 정리 완료: 연결추적 {}개, 포트스캔 {}개, 트래픽 {}개",
                connectionAttempts.size(), portScanAttempts.size(), trafficStats.size());
    }

    // =========================================================================
    // 🔧 유틸리티 메서드들
    // =========================================================================

    /**
     * 사설 IP 주소 확인
     */
    private boolean isPrivateIp(String ip) {
        return ip.startsWith("192.168.") ||
                ip.startsWith("10.") ||
                ip.startsWith("172.16.") ||
                ip.equals("127.0.0.1");
    }

    /**
     * 의심스러운 활동 알림 생성
     */
    private void createSuspiciousActivityAlert(String sourceIp, long packetCount) {
        Alert alert = Alert.builder()
                .alertType(AlertType.SUSPICIOUS_CONNECTION)
                .description(String.format(
                        "비정상적 활발한 네트워크 활동 탐지\n" +
                                "소스 IP: %s\n" +
                                "패킷 수: %d개 (5분간)\n" +
                                "의심 활동: 자동화된 도구 또는 봇 활동 가능성",
                        sourceIp, packetCount
                ))
                .severity(AlertSeverity.MEDIUM)
                .sourceIp(sourceIp)
                .build();

        alertService.createAlert(alert);
    }

    //  현재 탐지 상태 조회 (API용)
    public Map<String, Object> getDetectionStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("autoDetectionEnabled", detectionConfig.getEnableAutoDetection());
        status.put("activeConnectionTrackers", connectionAttempts.size());
        status.put("activePortScanTrackers", portScanAttempts.size());
        status.put("activeTrafficTrackers", trafficStats.size());
        status.put("detectionConfig", detectionConfig);
        return status;
    }
}