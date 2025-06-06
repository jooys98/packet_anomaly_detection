package org.example.packetanomalydetection.service.packetData;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.config.PacketCaptureConfig;
import org.example.packetanomalydetection.entity.PacketData;
import org.example.packetanomalydetection.handler.CaptureStatisticsManager;
import org.example.packetanomalydetection.networkInterface.NetworkInterfaceManager;
import org.example.packetanomalydetection.handler.PacketCaptureHandler;
import org.example.packetanomalydetection.handler.SimulationPacketCaptureHandler;
import org.example.packetanomalydetection.networkInterface.NetworkSystemValidator;
import org.example.packetanomalydetection.repository.PacketDataRepository;
import org.example.packetanomalydetection.service.threatDetection.ThreatDetectionService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

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

    private final PacketCaptureConfig captureConfig;
    private final PacketDataRepository packetRepository;
    private final ThreatDetectionService threatDetectionService;


    private final NetworkSystemValidator networkSystemValidator;
    private final NetworkInterfaceManager networkInterfaceManager;
    private final PacketCaptureHandler realCaptureHandler;
    private final SimulationPacketCaptureHandler simulationCaptureHandler;
    private final CaptureStatisticsManager statisticsManager;

    private boolean useSimulationMode = false;

    @PostConstruct
    public void initializeCapture() {
        log.info("PacketCaptureService 초기화 중...");

        // 캡처 모드 결정
        useSimulationMode = determineCaptureMode();

        if (captureConfig.getEnableCapture()) {
            startCapture();
        } else {
            log.warn("패킷 캡처 비활성화 상태");
        }
    }


    /**
     * 캡처 시작
     */
    public void startCapture() {
        log.info("패킷 캡처 시작 (모드: {})",
                useSimulationMode ? "시뮬레이션" : "실제 캡처");

        statisticsManager.startCapture();

        if (useSimulationMode) {
            simulationCaptureHandler.startCapture(this::handleCapturedPacket);
        } else {
            try {
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

    // 상태 조회 메서드들 (API용)
    public boolean isCapturing() {
        return useSimulationMode ?
                simulationCaptureHandler.isCapturing() :
                realCaptureHandler.isCapturing();
    }

    public long getTotalCapturedPackets() {
        return statisticsManager.getTotalCapturedPackets();
    }

    public LocalDateTime getLastPacketTime() {
        return statisticsManager.getLastPacketTime();
    }

    public String getSelectedInterfaceName() {
        return useSimulationMode ?
                "시뮬레이션 모드" :
                networkInterfaceManager.getSelectedInterfaceName();
    }

    public boolean isUsingSimulationMode() {
        return useSimulationMode;
    }
    /**
     * 캡처 모드 결정 로직
     */
    private boolean determineCaptureMode() {
        // Apple Silicon 체크
        if (networkSystemValidator.isAppleSiliconMac()) {
            log.warn("Apple Silicon Mac 감지 - 시뮬레이션 모드로 전환");
            return true;
        }

        // Pcap4J 호환성 체크
        if (!networkSystemValidator.testPcap4jCompatibility()) {
            log.warn("Pcap4J 호환성 문제 - 시뮬레이션 모드로 전환");
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

    @PreDestroy
    public void cleanup() {
        log.info("PacketCaptureService 정리 중...");
        stopCapture();
    }
}