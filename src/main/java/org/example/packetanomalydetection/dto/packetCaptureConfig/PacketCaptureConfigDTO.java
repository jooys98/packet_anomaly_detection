package org.example.packetanomalydetection.dto.packetCaptureConfig;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
public class PacketCaptureConfigDTO {

    private String interfaceName;           // 네트워크 인터페이스
    private Integer captureTimeout;         // 캡처 타임아웃
    private Integer bufferSize;             // 버퍼 크기
    private Boolean enableFilter;           // 필터 사용 여부
    private String filterMode;              // 필터 모드
    private String[] protocols;             // 프로토콜 필터
    private Integer[] ports;
}
