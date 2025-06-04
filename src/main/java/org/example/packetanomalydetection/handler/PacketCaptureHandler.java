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
 * 패킷 캡처 핸들러
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
    //Consumer : 함수형 인터페이스 - 콜백 함수를 저장해줌
    private Consumer<PacketData> packetHandler;

    /**
     * 패킷 캡처 시작
     * PcapNetworkInterface : 살제 네트워크 인터페이스를 제공해주는 pcap4j의 객체 (eth0,en0 ..)
     */
    @Async
    public void startCapture(PcapNetworkInterface networkInterface,
                             Consumer<PacketData> packetHandler) {
        //중복 실행 방지 검사
        if (isCapturing.get()) {
            log.info("실제 패킷 캡처가 이미 실행 중입니다");
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

        // Pcap 핸들 생성
        pcapHandle = networkInterface.openLive(
                snapLen,                                      // 캡처할 패킷의 최대 바이트
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,  //networkInterface - 해당 인터페이스의 모든 패킷을 캡처하는 설정 객체
                timeout                                       // 설정 해놓은 읽기 타임아웃
        );

        log.info("Pcap 핸들 생성 완료:");
        log.info("  - 스냅샷 길이: {} bytes", snapLen);
        log.info("  - 타임아웃: {} ms", timeout);
        log.info("  - 프로미스큐어스 모드: 활성화");
    }

    /**
     * 패킷 필터 설정
     * PacketFilterBuilder 에서 구축해놓은 패킷을 가져와서 적용시킴
     */
    private void setupPacketFilter() throws PcapNativeException, NotOpenException {
        String filter = filterBuilder.buildFilter(captureConfig.getFilter());

        //TODO : 성능개선 작업 - 필터가 없을 경우의 예외처리
        if (!filter.isEmpty()) {
            //BpfProgram: 하드웨어 레벨에서 패킷을 필터링(어플리케이션 레이어까지 올라오는 패킷수를 감소시킴)
            pcapHandle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            log.info("패킷 필터 설정: {}", filter);

        } else {
            throw new IllegalStateException("패킷 필터 미설정으로 인한 캡처 중단");
        }
    }

    /**
     * 실제 패킷 캡처 메인 루프
     */
    private void startRealCaptureLoop() throws PcapNativeException, NotOpenException, InterruptedException {
        // 패킷 리스너 설정 - 패킷이 올 때마다 이 메서드가 호출됨!
        PacketListener packetListener = new PacketListener() {
            @Override
            //패킷이 도착할 때마다 gotPacket() 자동 호
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
     *네트워크 패킷 처리
     */
    private void handleRealNetworkPacket(Packet packet) {
        try {
            // 패킷 파싱 - 네트워크 헤더에서 정보를 추출하여 PacketData 객체로 변환
            PacketData packetData = packetParser.parseNetworkPacket(packet);

            if (packetData != null && packetHandler != null) {
                packetHandler.accept(packetData);
                //PacketCaptureService 의 handleCapturedPacket 를 실행시킴
                // db 저장 -> 위협 탐지 시작
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
