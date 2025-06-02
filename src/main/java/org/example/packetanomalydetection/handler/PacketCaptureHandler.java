package org.example.packetanomalydetection.handler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.config.PacketCaptureConfig;
import org.example.packetanomalydetection.entity.PacketData;
import org.example.packetanomalydetection.util.PacketFilterBuilder;
import org.example.packetanomalydetection.util.PacketParser;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * 실제 패킷 캡처 핸들러
 *
 * 책임:
 * PacketFilterBuilder 의 구축된 필터를 호출하여 패킷을 캡처함
 * - 실제 네트워크 인터페이스에서 패킷 캡처
 * - Pcap4J를 이용한 저수준 패킷 처리
 * - 패킷 필터링 설정
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PacketCaptureHandler {

    private final PacketCaptureConfig captureConfig;
    private final PacketFilterBuilder filterBuilder;
    private final PacketParser packetParser;

    private PcapHandle pcapHandle;
    private final AtomicBoolean isCapturing = new AtomicBoolean(false);
    private Consumer<PacketData> packetHandler;

    /**
     * 실제 패킷 캡처 시작
     */
    @Async
    public void startCapture(PcapNetworkInterface networkInterface,
                             Consumer<PacketData> packetHandler) {
        if (isCapturing.get()) {
            log.warn("실제 패킷 캡처가 이미 실행 중입니다");
            return;
        }

        this.packetHandler = packetHandler;

        try {
            log.info("실제 패킷 캡처 시작");
            log.info("사용 인터페이스: {} ({})",
                    networkInterface.getName(),
                    networkInterface.getDescription());

            // Pcap 핸들 생성
            createPcapHandle(networkInterface);

            // 패킷 필터 설정
            setupPacketFilter();

            // 캡처 시작
            isCapturing.set(true);
            log.info("패킷 캡처 루프 시작 - 실시간 모니터링 개시!");

            startRealCaptureLoop();

        } catch (Exception e) {
            log.error("패킷 캡처 시작 실패", e);
            isCapturing.set(false);
            cleanupPcapHandle();
        }
    }

    /**
     * Pcap 핸들 생성 및 설정
     */
    private void createPcapHandle(PcapNetworkInterface networkInterface) throws PcapNativeException {
        // 설정값들을 불러와서 적용
        int snapLen = captureConfig.getBufferSize();     // 패킷 캡처 크기
        int timeout = captureConfig.getCaptureTimeout(); // 타임아웃 (ms)

        // Pcap 핸들 생성 (가장 중요한 부분!)
        pcapHandle = networkInterface.openLive(
                snapLen,                                      // 스냅샷 길이 (캡처할 최대 바이트)
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,  // 프로미스큐어스 모드 (모든 패킷 캡처)
                timeout                                       // 읽기 타임아웃
        );

        log.info("Pcap 핸들 생성 완료:");
        log.info("  - 스냅샷 길이: {} bytes", snapLen);
        log.info("  - 타임아웃: {} ms", timeout);
        log.info("  - 프로미스큐어스 모드: 활성화");
    }

    /**
     * 패킷 필터 설정 (선택적 기능)
     */
    private void setupPacketFilter() throws PcapNativeException, NotOpenException {
        String filter = filterBuilder.buildFilter(captureConfig.getFilter());

        if (!filter.isEmpty()) {
            pcapHandle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            log.info("패킷 필터 설정: {}", filter);
        } else {
            log.info("패킷 필터 없음 - 모든 패킷 캡처");
        }
    }

    /**
     * 실제 패킷 캡처 메인 루프
     */
    private void startRealCaptureLoop() throws PcapNativeException, NotOpenException, InterruptedException {
        // 패킷 리스너 설정 - 패킷이 올 때마다 이 메서드가 호출됨!
        PacketListener packetListener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                try {
                    handleRealNetworkPacket(packet);
                } catch (Exception e) {
                    log.error("패킷 처리 중 오류", e);
                }
            }
        };

        // 무한 루프로 패킷 캡처 시작
        pcapHandle.loop(-1, packetListener);
    }

    /**
     * 실제 네트워크 패킷 처리
     */
    private void handleRealNetworkPacket(Packet packet) {
        try {
            // 패킷 파싱 - 네트워크 헤더에서 정보 추출
            PacketData packetData = packetParser.parseNetworkPacket(packet);

            if (packetData != null && packetHandler != null) {
                packetHandler.accept(packetData);
            }

        } catch (Exception e) {
            log.error("실제 패킷 처리 중 오류", e);
        }
    }

    /**
     * 캡처 중지
     */
    public void stopCapture() {
        if (!isCapturing.get()) {
            log.warn("실제 패킷 캡처가 실행되고 있지 않습니다");
            return;
        }

        log.info("실제 패킷 캡처 중지 요청");
        isCapturing.set(false);

        try {
            if (pcapHandle != null && pcapHandle.isOpen()) {
                pcapHandle.breakLoop();
                log.info("패킷 캡처 루프 중단됨");
            }
        } catch (NotOpenException e) {
            log.error("캡처 중지 중 오류", e);
        }

        cleanupPcapHandle();
    }

    /**
     * Pcap 핸들 정리
     */
    private void cleanupPcapHandle() {
        if (pcapHandle != null) {
            try {
                pcapHandle.close();
                log.info("Pcap 핸들 정리 완료");
            } catch (Exception e) {
                log.error("Pcap 핸들 정리 중 오류", e);
            } finally {
                pcapHandle = null;
            }
        }
    }

    /**
     * 캡처 상태 확인
     */
    public boolean isCapturing() {
        return isCapturing.get();
    }
}
