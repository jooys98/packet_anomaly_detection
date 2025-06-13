package org.example.packetanomalydetection.handler;


import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.entity.CaptureStatistics;
import org.example.packetanomalydetection.entity.enums.CaptureMode;
import org.example.packetanomalydetection.entity.enums.CaptureStatus;
import org.example.packetanomalydetection.repository.CaptureStatisticsRepository;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.UUID;
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
@RequiredArgsConstructor
public class CaptureStatisticsManager {


    // 통계 관련 변수들
    private final AtomicLong totalCapturedPackets = new AtomicLong(0);
    private final AtomicLong packetsPerSecondCounter = new AtomicLong(0);
    private final AtomicBoolean isActive = new AtomicBoolean(false);

    // 시간 관련 변수들

    private String currentSessionId;
    private CaptureStatistics currentStatistics;
    private LocalDateTime captureStartTime;
    private double peakPacketsPerSecond = 0.0;
    private long lastStatsPrintTime = 0;
    private LocalDateTime captureEndTime;
    // 출력 제어 변수들
    private static final int PROGRESS_PRINT_INTERVAL_SIMULATION = 50; // 시뮬레이션: 50개마다
    private static final int STATS_PRINT_INTERVAL_SECONDS = 10;       // 통계: 10초마다


    private final CaptureStatisticsRepository captureStatisticsRepository;


    /**
     * 캡처 시작 - 통계 초기화
     */
    public void startCapture(CaptureMode mode, String networkInterface) {
        currentSessionId = UUID.randomUUID().toString();
        captureStartTime = LocalDateTime.now();

        if (networkInterface == null) {
            networkInterface = "SIMULATION";
        }
        currentStatistics = CaptureStatistics.from(currentSessionId, captureStartTime, mode, networkInterface);

        isActive.set(true);
        captureStartTime = LocalDateTime.now();
        totalCapturedPackets.set(0);
        packetsPerSecondCounter.set(0);
        lastStatsPrintTime = System.currentTimeMillis() / 1000;


        currentStatistics.updateStatus(CaptureStatus.ACTIVE);
        log.info("통계 관리 시작: {}", captureStartTime);
    }

    /**
     * 패킷 처리 통계 업데이트
     */
    public void updateStats() {
        totalCapturedPackets.incrementAndGet();
        packetsPerSecondCounter.incrementAndGet();
        // 주기적으로 PPS 통계 출력
        printPeriodicStats();
    }

    /**
     * 진행 상황 출력 여부 결정
     */
    public boolean shouldPrintProgress() {
        long total = totalCapturedPackets.get();

        // 시뮬레이션 모드: 50개마다, 실제 모드: 100개마다
        return total % PROGRESS_PRINT_INTERVAL_SIMULATION == 0;
    }


    /**
     * 캡처 중지
     */
    public void stopCapture() {
        if (currentStatistics == null) {
            log.info("저장할 통계 세션이 없음");
            return;
        }

        isActive.set(false);
        log.info("통계 관리 중지");
        captureEndTime = LocalDateTime.now();
        long runningSeconds = java.time.Duration.between(captureStartTime, captureEndTime).getSeconds();
        double avgPps = runningSeconds > 0 ? (double) totalCapturedPackets.get() / runningSeconds : 0;

        // 최종 통계 업데이트
        currentStatistics.updateStatistics(captureEndTime, totalCapturedPackets.get(), runningSeconds,
                avgPps, peakPacketsPerSecond);

        // 상태 변경
        currentStatistics.updateStatus(CaptureStatus.STOPPED);

        // DB 저장
        captureStatisticsRepository.save(currentStatistics);


        log.info("통계 세션 종료: {}", currentSessionId);
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

        if (captureEndTime != null) {
            log.info("마지막 패킷: {}", captureEndTime);
        }

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




}