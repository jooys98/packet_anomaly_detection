package org.example.packetanomalydetection.util.tracker;


import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.entity.PacketData;

import java.time.LocalDateTime;
import java.util.*;

/**
 * ConnectionAttemptTracker - 연결 시도 추적기
 * 역할: 특정 IP 에서 오는 연결 시도를 추적해서 브루트포스 공격 탐지
 * 동작 원리:
 * 1. IP 별로 연결 시도 시간과 대상을 기록
 * 2. 설정된 시간 윈도우 내의 시도 횟수 계산
 * 3. 임계값 초과 시 브루트포스 공격으로 판단
 * 예시:
 * - 192.168.1.50에서 5분간 SSH 포트(22)에 100번 연결 시도
 * → 브루트포스 공격으로 탐지
 */
@Getter
@Slf4j
public class ConnectionAttemptTracker {

    // 연결 시도 기록들 (시간순으로 저장)
    private final List<ConnectionAttempt> attempts = new ArrayList<>();

    //  마지막 활동 시간 (메모리 정리용)
    private LocalDateTime lastActivity = LocalDateTime.now();

    /**
     * 새로운 연결 시도 추가
     */
    public synchronized void addAttempt(PacketData packet) {
        ConnectionAttempt attempt = new ConnectionAttempt(
                LocalDateTime.now(),
                packet.getDestIp(),
                packet.getDestPort(),
                packet.getProtocol()
        );

        attempts.add(attempt);
        lastActivity = LocalDateTime.now();

        // 메모리 관리: 너무 오래된 시도는 제거 (1시간 이상)
        cleanupOldAttempts(60);

        log.debug("연결 시도 기록: {} → {}:{}",
                packet.getSourceIp(), packet.getDestIp(), packet.getDestPort());
    }

    /**
     * 지정된 시간(분) 내의 연결 시도 수 계산
     */
    public synchronized int getAttemptsInLastMinutes(int minutes) {
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(minutes);

        int count = (int) attempts.stream()
                .filter(attempt -> attempt.timestamp().isAfter(cutoff))
                .count();

        log.debug("최근 {}분간 연결 시도: {}회", minutes, count);
        return count;
    }

    /**
     * 특정 포트에 대한 연결 시도 수
     */
    public synchronized int getAttemptsToPort(int port, int minutes) {
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(minutes);

        return (int) attempts.stream()
                .filter(attempt -> attempt.timestamp().isAfter(cutoff))
                .filter(attempt -> Objects.equals(attempt.targetPort(), port))
                .count();
    }

    /**
     * 추적기 리셋 (알림 생성 후 중복 방지용)
     */
    public synchronized void reset() {
        attempts.clear();
        lastActivity = LocalDateTime.now();
        log.debug(" 연결 시도 추적기 리셋");
    }

    /**
     * 총 연결 시도 수
     */
    public synchronized int getTotalAttempts() {
        return attempts.size();
    }

    /**
     * 오래된 시도 기록 제거
     */
    private void cleanupOldAttempts(int maxAgeMinutes) {
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(maxAgeMinutes);
        attempts.removeIf(attempt -> attempt.timestamp().isBefore(cutoff));
    }


    /**
     * 연결 시도 데이터 클래스
     */
    @Getter
    public record ConnectionAttempt(
            LocalDateTime timestamp,
            String targetIp,
            Integer targetPort,
            String protocol) {

        @Override
        public String toString() {
            return String.format("[%s] %s:%s (%s)",
                    timestamp, targetIp, targetPort, protocol);
        }
    }
}