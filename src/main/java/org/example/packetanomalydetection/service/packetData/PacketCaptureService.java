package org.example.packetanomalydetection.service.packetData;

import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.entity.PacketData;
import org.example.packetanomalydetection.handler.CaptureStatisticsManager;
import org.example.packetanomalydetection.networkInterface.NetworkInterfaceManager;
import org.example.packetanomalydetection.handler.PacketCaptureHandler;
import org.example.packetanomalydetection.handler.SimulationPacketCaptureHandler;
import org.example.packetanomalydetection.networkInterface.NetworkSystemValidator;
import org.example.packetanomalydetection.repository.PacketDataRepository;
import org.example.packetanomalydetection.service.threatDetection.ThreatDetectionService;
import org.springframework.stereotype.Service;

import java.util.concurrent.atomic.AtomicBoolean;


/**
 * 패킷 캡처 서비스 - 메인 조정자 역할
 * 책임:
 * - 캡처 모드 결정 (실제 vs 시뮬레이션)
 * - 각 하위 컴포넌트 조정
 * - 전체 생명주기 관리
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PacketCaptureService {

    private final PacketDataRepository packetRepository;
    private final ThreatDetectionService threatDetectionService;


    private final NetworkSystemValidator networkSystemValidator;
    private final NetworkInterfaceManager networkInterfaceManager;
    private final PacketCaptureHandler realCaptureHandler;
    private final SimulationPacketCaptureHandler simulationCaptureHandler;
    private final CaptureStatisticsManager statisticsManager;

    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    boolean useSimulationMode;


    public void initializeCapture() {
        if (isRunning.get()) {
            log.warn("패킷 캡처가 이미 실행 중입니다");
            return;
        }

        log.info(" 패킷 캡처 초기화 시작...");

        try {
            // 캡처 모드 결정
            boolean captureMode = determineCaptureMode();

            // 별도 스레드에서 캡처 시작
            startCaptureInBackground(captureMode);

            isRunning.set(true);
            log.info("패킷 캡처 초기화 완료 (모드: {})", getCaptureMode());

        } catch (Exception e) {
            log.error(" 패킷 캡처 초기화 실패: {}", e.getMessage(), e);
            isRunning.set(false);
            throw new RuntimeException("패킷 캡처 초기화 실패", e);
        }
    }

    private void startCaptureInBackground(boolean captureMode) {
        // 100ms 대기
        // 오류가 발생해도 계속 시도 (필요에 따라 조정)
        Thread captureThread = new Thread(() -> {
            log.info("백그라운드 패킷 캡처 시작");


            while (isRunning.get() && !Thread.currentThread().isInterrupted()) {
                try {
                    if (captureMode) {
                        useSimulationMode = true;
                        simulationCaptureHandler.startCapture(this::handleCapturedPacket);
                    } else {
                        try {
                            useSimulationMode = false;
                            networkInterfaceManager.initializeInterface();
                            realCaptureHandler.startCapture(
                                    networkInterfaceManager.getSelectedInterface(),
                                    this::handleCapturedPacket
                            );
                        } catch (Exception e) {
                            log.error("실제 패킷 캡처 시작 실패 - 시뮬레이션 모드로 전환", e);
                            useSimulationMode = true;
                            simulationCaptureHandler.startCapture(this::handleCapturedPacket);
                        }
                    }

                    Thread.sleep(100); // 100ms 대기

                } catch (InterruptedException e) {
                    log.info("패킷 캡처 스레드 중단 요청");
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    log.error(" 패킷 캡처 중 오류: {}", e.getMessage(), e);
                    // 오류가 발생해도 계속 시도 (필요에 따라 조정)
                }
            }

            log.info(" 패킷 캡처 스레드 종료");
        }, "PacketCaptureThread");

        captureThread.setDaemon(true); // 데몬 스레드로 설정
        captureThread.start();

        log.info("패킷 캡처 백그라운드 스레드 시작됨");
    }


    @PreDestroy
    public boolean cleanup() {
        log.info("PacketCaptureService 정리 중...");
        stopCapture();
        return true;
    }

    /**
     * 캡처 중지
     */
    public void stopCapture() {
        log.info("패킷 캡처 중지 요청");

        if (useSimulationMode) {
            simulationCaptureHandler.stopCapture();

        } else {
            realCaptureHandler.stopCapture();
        }

        statisticsManager.stopCapture();
        statisticsManager.printFinalStats(useSimulationMode);
    }


    /**
     * 캡처 모드 결정 로직
     */
    private boolean determineCaptureMode() {
        // Apple Silicon 체크
        if (networkSystemValidator.isAppleSiliconMac()||networkSystemValidator.testPcap4jCompatibility()) {
            log.warn("Apple Silicon Mac 감지 - 시뮬레이션 모드로 전환");
            return true;
        }
        return false;
    }


    /**
     * 캡처된 패킷 처리 (콜백 메서드)
     */
    private void handleCapturedPacket(PacketData packetData) {
        try {
            // 데이터베이스 저장
            PacketData savedPacket = packetRepository.save(packetData);

            // 통계 업데이트
            statisticsManager.updateStats();

            // 위협 탐지
            threatDetectionService.analyzePacketRealtime(savedPacket);

            // 진행 상황 출력
            if (statisticsManager.shouldPrintProgress()) {
                printCaptureProgress(savedPacket);
            }

        } catch (Exception e) {
            log.error("패킷 처리 중 오류", e);
        }
    }

    /**
     * 캡처 진행 상황 출력
     */
    private void printCaptureProgress(PacketData packet) {
        System.out.printf("[%s #%d] %s:%s -> %s:%s (%s, %d bytes)\n",
                useSimulationMode ? "시뮬레이션" : "실제 패킷",
                statisticsManager.getTotalCapturedPackets(),
                packet.getSourceIp(),
                packet.getSourcePort() != null ? packet.getSourcePort() : "?",
                packet.getDestIp(),
                packet.getDestPort() != null ? packet.getDestPort() : "?",
                packet.getProtocol(),
                packet.getPacketSize()
        );
    }

    public boolean isRunning() {
        return isRunning.get();
    }


    private String getCaptureMode() {
        return useSimulationMode ? "SIMULATION" : "REAL";
    }


}