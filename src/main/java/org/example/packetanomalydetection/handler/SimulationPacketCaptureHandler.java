package org.example.packetanomalydetection.handler;

import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.entity.PacketData;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;


/**
 * 시뮬레이션 패킷 캡처 핸들러
 * 책임:
 * - Apple Silicon 등 호환성 문제 환경에서 가상 패킷 생성
 * - 다양한 공격 시나리오 시뮬레이션
 * - 학습용 테스트 데이터 제공
 */
@Component
@Slf4j
public class SimulationPacketCaptureHandler {

    private final AtomicBoolean isCapturing = new AtomicBoolean(false);
    private Consumer<PacketData> packetHandler;
    private ScheduledExecutorService executorService;
    private ScheduledFuture<?> captureTask;


    /**
     * 시뮬레이션 캡처 시작
     */
    @Async
    public void startCapture(Consumer<PacketData> packetHandler) {
        if (isCapturing.get()) {
            log.warn("시뮬레이션 캡처가 이미 실행 중입니다");
            return;
        }

        this.packetHandler = packetHandler;
        isCapturing.set(true);

        log.info("시뮬레이션 모드 패킷 캡처 시작");
        log.info("학습 목적: 실제 패킷 대신 가상 데이터로 위협 탐지 테스트");

        startSimulationLoop();
    }
    /**
     * 캡처 중지
     */
    public void stopCapture() {
        if (isCapturing.get()) {
            log.info("시뮬레이션 캡처 중지");
            isCapturing.set(false);
        }// 실행 중인 태스크 중단
        if (captureTask != null && !captureTask.isCancelled()) {
            captureTask.cancel(true);
        }

        // ExecutorService 종료
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
            try {
                if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                    executorService.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            } catch (InterruptedException e) {
                executorService.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        log.info("시뮬레이션 캡처 완전 중지됨");
    }



    /**
     * 시뮬레이션 루프
     */
    private void startSimulationLoop() {
        while (isCapturing.get()) {
            try {
                // 가상 패킷 생성
                PacketData simulatedPacket = generateSimulatedPacket();

                if (simulatedPacket != null && packetHandler != null) {
                    packetHandler.accept(simulatedPacket);
                }

                // 시뮬레이션 속도 조절 (0.5초마다 패킷 생성)
                Thread.sleep(500);

            } catch (InterruptedException e) {
                log.info("시뮬레이션 루프 중단됨");
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("시뮬레이션 패킷 처리 중 오류", e);
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 시뮬레이션 패킷 생성 (다양한 공격 시나리오)
     */
    private PacketData generateSimulatedPacket() {
        double random = Math.random();

        if (random < 0.6) {
            return generateNormalTraffic();        // 60% - 정상 트래픽
        } else if (random < 0.7) {
            return generatePortScanAttack();       // 포트 스캔 공격
        } else if (random < 0.75) {
            return generateBruteForceAttack();     // 브루트포스 공격
        } else if (random < 0.8) {
            return generateSmurfAttack();          // ICMP 스머프공격
        } else if (random < 0.85) {
            return generatePingFloodAttack();      //Ping Flood 공격
        }else if (random < 0.9) {
            return generatePingOfDeathAttack();    //Ping of Death 공격
        }
        else if (random < 0.95) {
            return generateLargePacketAttack();    // 5% - 대용량 패킷 공격
        } else {
            return generateSuspiciousActivity();   // 5% - 의심스러운 활동
        }
    }

    /**
     * 정상 트래픽 생성
     */
    private PacketData generateNormalTraffic() {
        String[] normalIps = {"192.168.1.10", "192.168.1.15", "192.168.1.20"};
        String[] webServers = {"8.8.8.8", "1.1.1.1", "74.125.224.72"};
        Integer[] normalPorts = {80, 443, 53};

        return PacketData.builder()
                .sourceIp(normalIps[(int)(Math.random() * normalIps.length)])
                .destIp(webServers[(int)(Math.random() * webServers.length)])
                .sourcePort(49152 + (int)(Math.random() * 16000))
                .destPort(normalPorts[(int)(Math.random() * normalPorts.length)])
                .protocol("TCP")
                .packetSize(200 + (int)(Math.random() * 800))
                .payloadLength(100 + (int)(Math.random() * 600))
                .flags("ACK")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * 포트 스캔 공격 생성
     */
    private PacketData generatePortScanAttack() {
        Integer[] targetPorts = {22, 23, 21, 80, 443, 3389, 1433, 3306};

        return PacketData.builder()
                .sourceIp("203.0.113.50") // 공격자 IP (고정)
                .destIp("192.168.1.100")  // 대상 서버 (고정)
                .sourcePort(12345)
                .destPort(targetPorts[(int)(Math.random() * targetPorts.length)])
                .protocol("TCP")
                .packetSize(64)
                .payloadLength(0)
                .flags("SYN")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * 브루트포스 공격 생성 (SSH)
     */
    private PacketData generateBruteForceAttack() {
        return PacketData.builder()
                .sourceIp("198.51.100.75") // 브루트포스 공격자
                .destIp("192.168.1.200")   // SSH 서버
                .sourcePort(54321)
                .destPort(22) // SSH 포트에 집중 공격
                .protocol("TCP")
                .packetSize(128)
                .payloadLength(64)
                .flags("PSH,ACK")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * 대용량 패킷 공격 생성
     */
    private PacketData generateLargePacketAttack() {
        return PacketData.builder()
                .sourceIp("172.16.0.50")
                .destIp("192.168.1.100")
                .sourcePort(8080)
                .destPort(80)
                .protocol("TCP")
                .packetSize(8000) // 임계값(1500) 초과!
                .payloadLength(7800)
                .flags("PSH,ACK")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * 의심스러운 DB 포트 접근 생성
     */
    private PacketData generateSuspiciousActivity() {
        Integer[] dbPorts = {1433, 3306, 5432, 6379, 27017}; // DB 포트들

        return PacketData.builder()
                .sourceIp("10.0.0.99")
                .destIp("192.168.1.150")
                .sourcePort(33333)
                .destPort(dbPorts[(int)(Math.random() * dbPorts.length)])
                .protocol("TCP")
                .packetSize(256)
                .payloadLength(128)
                .flags("SYN")
                .timestamp(LocalDateTime.now())
                .build();
    }

    //Ping Flood 공격
    private PacketData generatePingFloodAttack() {
        return PacketData.builder()
                .sourceIp("203.0.113.45")     // 외부 공격자
                .destIp("192.168.1.1")       // 내부 게이트웨이/서버
                .sourcePort(0)               // ICMP는 포트 개념 없음
                .destPort(0)
                .protocol("ICMP")
                .packetSize(1500)            // 큰 ICMP 패킷으로 부하 증가
                .payloadLength(1472)         // MTU 최대 활용
                .flags("ECHO_REQUEST")       // ICMP Echo Request
                .timestamp(LocalDateTime.now())
                .build();
    }

    //Ping of Death 공격
    private PacketData generatePingOfDeathAttack() {
        return PacketData.builder()
                .sourceIp("198.51.100.33")   // 악의적 호스트
                .destIp("192.168.1.100")     // 대상 서버
                .sourcePort(0)
                .destPort(0)
                .protocol("ICMP")
                .packetSize(65536)           // 비정상적으로 큰 패킷 (64KB)
                .payloadLength(65508)        // IP 헤더 최대 크기 고려
                .flags("ECHO_REQUEST")
                .timestamp(LocalDateTime.now())
                .build();
    }


    //Smurf 공격
    private PacketData generateSmurfAttack() {
        return PacketData.builder()
                .sourceIp("192.168.1.100")   // 피해자 IP로 스푸핑
                .destIp("192.168.1.255")     // 브로드캐스트 주소
                .sourcePort(0)
                .destPort(0)
                .protocol("ICMP")
                .packetSize(84)
                .payloadLength(56)
                .flags("ECHO_REQUEST")       // 브로드캐스트 ping
                .timestamp(LocalDateTime.now())
                .build();
    }
}