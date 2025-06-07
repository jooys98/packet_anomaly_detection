package org.example.packetanomalydetection.dto.packetStatus;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PacketCaptureStatusResponseDTO {
    private boolean isRunning;              // 캡처 실행 여부
    private String captureMode;             // REAL, SIMULATION
    private String interfaceName;           // 네트워크 인터페이스 이름
    private LocalDateTime startTime;        // 시작 시간
    private LocalDateTime lastPacketTime;   // 마지막 패킷 수신 시간
    private Long totalPacketsProcessed;     // 총 처리된 패킷 수
    private Double packetsPerSecond;        // 초당 패킷 수
    private String errorMessage;            // 오류 메시지 (있을 경우)
    private LocalDateTime timestamp;        // 응답 시간
}
