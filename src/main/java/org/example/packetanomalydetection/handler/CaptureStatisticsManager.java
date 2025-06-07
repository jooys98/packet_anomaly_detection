package org.example.packetanomalydetection.handler;


import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 패킷 캡처 통계 관리 전담 클래스
 * 책임:
 * - 캡처된 패킷 수 추적
 * - 처리량 계산 (PPS - Packets Per Second)
 * - 성능 모니터링
 * - 진행 상황 출력 제어
 */
@Component
@Slf4j
@Getter
public class CaptureStatisticsManager {

    // 통계 관련 변수들
    private final AtomicLong totalCapturedPackets = new AtomicLong(0);
    private final AtomicLong packetsPerSecondCounter = new AtomicLong(0);
    private final AtomicBoolean isActive = new AtomicBoolean(false);

    // 시간 관련 변수들

    private LocalDateTime captureStartTime;
    @Getter
    private LocalDateTime lastPacketTime;
    private long lastStatsPrintTime = 0;

    // 출력 제어 변수들
    private static final int PROGRESS_PRINT_INTERVAL_SIMULATION = 50; // 시뮬레이션: 50개마다
    private static final int PROGRESS_PRINT_INTERVAL_REAL = 100;      // 실제: 100개마다
    private static final int STATS_PRINT_INTERVAL_SECONDS = 10;       // 통계: 10초마다

    /**
     * 캡처 시작 - 통계 초기화
     */
    public void startCapture() {
        isActive.set(true);
        captureStartTime = LocalDateTime.now();
        totalCapturedPackets.set(0);
        packetsPerSecondCounter.set(0);
        lastStatsPrintTime = System.currentTimeMillis() / 1000;

        log.info("통계 관리 시작: {}", captureStartTime);
    }

    /**
     * 패킷 처리 통계 업데이트
     */
    public void updateStats() {
        totalCapturedPackets.incrementAndGet();
        packetsPerSecondCounter.incrementAndGet();
        lastPacketTime = LocalDateTime.now();

        // 주기적으로 PPS 통계 출력
        printPeriodicStats();
    }

    /**
     * 진행 상황 출력 여부 결정
     */
    public boolean shouldPrintProgress() {
        long total = totalCapturedPackets.get();

        // 시뮬레이션 모드: 50개마다, 실제 모드: 100개마다
        // TODO: 모드 구분을 위해 파라미터 추가 고려
        return total % PROGRESS_PRINT_INTERVAL_SIMULATION == 0;
    }

    /**
     * 실제 캡처 모드의 진행 상황 출력 여부
     */
    public boolean shouldPrintProgressForRealCapture() {
        return totalCapturedPackets.get() % PROGRESS_PRINT_INTERVAL_REAL == 0;
    }

    /**
     * 캡처 중지
     */
    public void stopCapture() {
        isActive.set(false);
        log.info("통계 관리 중지");
    }

    /**
     * 최종 통계 출력
     */
    public void printFinalStats(boolean isSimulationMode) {
        if (captureStartTime == null) {
            log.warn("캡처 시작 시간이 기록되지 않음");
            return;
        }

        LocalDateTime endTime = LocalDateTime.now();
        long runningSeconds = java.time.Duration.between(captureStartTime, endTime).getSeconds();
        double avgPacketsPerSecond = runningSeconds > 0 ?
                (double) totalCapturedPackets.get() / runningSeconds : 0;

        log.info("=== 패킷 캡처 최종 통계 ({} 모드) ===",
                isSimulationMode ? "시뮬레이션" : "실제");
        log.info("총 처리 패킷: {} 개", totalCapturedPackets.get());
        log.info("실행 시간: {} 초", runningSeconds);
        log.info("평균 처리량: {:.2f} 패킷/초", avgPacketsPerSecond);
        log.info("시작 시간: {}", captureStartTime);
        log.info("종료 시간: {}", endTime);

        if (lastPacketTime != null) {
            log.info("마지막 패킷: {}", lastPacketTime);
        }

        // 성능 평가
        printPerformanceAssessment(avgPacketsPerSecond, isSimulationMode);
    }

    /**
     * 주기적 통계 출력 (10초마다)
     */
    private void printPeriodicStats() {
        long currentSecond = System.currentTimeMillis() / 1000;

        if (currentSecond - lastStatsPrintTime >= STATS_PRINT_INTERVAL_SECONDS) {
            long packetsInPeriod = packetsPerSecondCounter.getAndSet(0);
            double pps = (double) packetsInPeriod / STATS_PRINT_INTERVAL_SECONDS;

            log.info("처리량 통계: {:.1f} 패킷/초 (총 {} 개 처리됨)",
                    pps, totalCapturedPackets.get());

            lastStatsPrintTime = currentSecond;
        }
    }


    /**
     * 성능 평가 출력
     */
    private void printPerformanceAssessment(double avgPps, boolean isSimulationMode) {
        log.info("=== 성능 평가 ===");

        if (isSimulationMode) {
            log.info("시뮬레이션 모드 - 성능 테스트 완료");
            if (avgPps >= 1.0) {
                log.info("시뮬레이션 성능: 양호 ({:.1f} PPS)", avgPps);
            } else {
                log.warn("시뮬레이션 성능: 느림 ({:.1f} PPS)", avgPps);
            }
        } else {
            // 실제 캡처 모드 성능 평가
            if (avgPps >= 100) {
                log.info(" 실제 캡처 성능: 우수 ({:.1f} PPS)", avgPps);
            } else if (avgPps >= 50) {
                log.info("실제 캡처 성능: 양호 ({:.1f} PPS)", avgPps);
            } else if (avgPps >= 10) {
                log.warn("실제 캡처 성능: 보통 ({:.1f} PPS)", avgPps);
            } else {
                log.warn(" 실제 캡처 성능: 개선 필요 ({:.1f} PPS)", avgPps);
            }
        }
    }

    /**
     * 현재 처리량 조회 (API용)
     */
    public double getCurrentPacketsPerSecond() {
        long currentTime = System.currentTimeMillis() / 1000;
        long timeDiff = currentTime - lastStatsPrintTime;

        if (timeDiff > 0) {
            return (double) packetsPerSecondCounter.get() / timeDiff;
        }
        return 0.0;
    }



    public long getTotalCapturedPackets() {
        return totalCapturedPackets.get();
    }

    /**
     * 실행 시간 조회 (초 단위)
     */
    public long getRunningTimeSeconds() {
        if (captureStartTime == null) {
            return 0;
        }
        return java.time.Duration.between(captureStartTime, LocalDateTime.now()).getSeconds();
    }

    /**
     * 평균 처리량 조회
     */
    public double getAveragePacketsPerSecond() {
        long runningSeconds = getRunningTimeSeconds();
        return runningSeconds > 0 ? (double) totalCapturedPackets.get() / runningSeconds : 0.0;
    }


}