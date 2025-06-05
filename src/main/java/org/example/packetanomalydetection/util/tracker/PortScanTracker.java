package org.example.packetanomalydetection.util.tracker;


import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.entity.enums.ScanPattern;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 *  PortScanTracker - 포트 스캔 추적기
 *
 * 역할: 특정 IP 에서 여러 포트에 접근하는 패턴을 추적해서 포트 스캔 탐지
 *
 * 포트 스캔의 특징:
 * 1. 짧은 시간에 여러 포트 접근
 * 2. 대부분 연결 실패 (포트가 닫혀있음)
 * 3. 순차적 또는 무작위 포트 스캔
 *
 * 예시:
 * - 203.0.113.50에서 22, 23, 80, 443, 3389, 21 포트 순차 접근
 * → 포트 스캔 공격으로 탐지
 */
@Getter
@Slf4j
public class PortScanTracker {

    // 접근한 포트와 시간 기록
    private final Map<Integer, LocalDateTime> scannedPorts = new ConcurrentHashMap<>();

    // 접근한 대상 IP들
    private final Set<String> targetIps = ConcurrentHashMap.newKeySet();

    // 의심스러운 시스템 포트 접근 기록
    private final Set<Integer> suspiciousPortsAccessed = ConcurrentHashMap.newKeySet();

    // 마지막 활동 시간
    private LocalDateTime lastActivity = LocalDateTime.now();

    //  의심스러운 포트 목록 (시스템 관리용 포트들)
    private static final Set<Integer> SUSPICIOUS_PORTS = Set.of(
            22, 23, 3389, 21, 135, 139, 445, 1433, 3306, 5432, 6379, 27017
    );

    /**
     *  포트 접근 기록 추가
     */
    public synchronized void addPortAccess(int port, String targetIp) {
        scannedPorts.put(port, LocalDateTime.now());
        targetIps.add(targetIp);
        lastActivity = LocalDateTime.now();

        //  의심스러운 포트인지 확인
        if (SUSPICIOUS_PORTS.contains(port)) {
            suspiciousPortsAccessed.add(port);
            log.debug(" 의심스러운 포트 접근: {}", port);
        }

        log.debug(" 포트 스캔 기록: 포트 {} → {}", port, targetIp);

        //  오래된 기록 정리 (30분 이상)
        cleanupOldScans(30);
    }

    /**
     *  고유 포트 수 (중복 제거)
     */
    public synchronized int getUniquePortCount() {
        return scannedPorts.size();
    }

    /**
     *  의심스러운 포트 접근 수
     */
    public synchronized int getSuspiciousPortCount() {
        return suspiciousPortsAccessed.size();
    }

    /**
     *  스캔된 포트 목록
     */
    public synchronized Set<Integer> getScannedPorts() {
        return new HashSet<>(scannedPorts.keySet());
    }

    /**
     *  대상 IP 목록
     */
    public synchronized Set<String> getTargetIps() {
        return new HashSet<>(targetIps);
    }

    /**
     * 스캔 지속 시간 (분)
     */
    public synchronized long getScanDurationMinutes() {
        if (scannedPorts.isEmpty()) return 0;

        LocalDateTime earliest = scannedPorts.values().stream()
                .min(LocalDateTime::compareTo)
                .orElse(LocalDateTime.now());

        LocalDateTime latest = scannedPorts.values().stream()
                .max(LocalDateTime::compareTo)
                .orElse(LocalDateTime.now());

        return java.time.Duration.between(earliest, latest).toMinutes();
    }

    /**
     *  오래된 스캔 기록 정리
     */
    private void cleanupOldScans(int maxAgeMinutes) {
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(maxAgeMinutes);

        scannedPorts.entrySet().removeIf(entry ->
                entry.getValue().isBefore(cutoff)
        );

        // 의심스러운 포트 기록도 정리
        suspiciousPortsAccessed.removeIf(port ->
                !scannedPorts.containsKey(port)
        );
    }

    /**
     *  추적기 리셋
     */
    public synchronized void reset() {
        scannedPorts.clear();
        targetIps.clear();
        suspiciousPortsAccessed.clear();
        lastActivity = LocalDateTime.now();
        log.debug(" 포트 스캔 추적기 리셋");
    }

    /**
     *  스캔 패턴 분석
     */
    public synchronized ScanPattern analyzeScanPattern() {
        if (scannedPorts.size() < 3) {
            return ScanPattern.INSUFFICIENT_DATA;
        }

        List<Integer> sortedPorts = scannedPorts.keySet().stream()
                .sorted()
                .toList();

        //  순차적 스캔인지 확인 (연속된 포트 번호)
        boolean isSequential = true;
        for (int i = 1; i < sortedPorts.size(); i++) {
            if (sortedPorts.get(i) - sortedPorts.get(i-1) > 5) {
                isSequential = false;
                break;
            }
        }

        if (isSequential) {
            return ScanPattern.SEQUENTIAL;
        }

        //  일반적인 포트들인지 확인
        Set<Integer> commonPorts = Set.of(21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389);
        long commonPortCount = sortedPorts.stream()
                .filter(commonPorts::contains)
                .count();

        if (commonPortCount >= sortedPorts.size() * 0.7) {
            return ScanPattern.COMMON_PORTS;
        }

        return ScanPattern.RANDOM;
    }



}