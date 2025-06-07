package org.example.packetanomalydetection.config;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;


@Component
@NoArgsConstructor
@Getter

/*
 * 패킷 캡처 관련 설정
 **/

public class PacketCaptureConfig {

    //패킷을 캡처할 네트워크 인터페이스 이름
    //eth0 : 리눅스에서 일반적인 인터페이스 이름
    private String interfaceName;

    //1000ms = 1초 (1초마다 한번씩 캠처된 패킷들을 정리)
    /*
     * Timeout 이 짧을 때 (100ms):
     * - 장점: 실시간성 높음, 빠른 위협 탐지
     * - 단점: CPU 사용량 높음, 시스템 부하 증가
     *
     * Timeout 이 길 때 (5000ms):
     * - 장점: 효율적인 배치 처리, 낮은 시스템 부하
     * - 단점: 위협 탐지 지연, 실시간성 떨어짐
     */
    private Integer captureTimeout;

    //패킷 캡처용 메모리 버퍼 크기
    /*
     * 버퍼가 작을 때:
     * - 메모리 사용량 적음
     * - 고트래픽 상황에서 패킷 손실 위험
     *
     * 버퍼가 클 때:
     * - 패킷 손실 위험 적음
     * - 메모리 사용량 증가
     */
    private Integer bufferSize;

    //패킷 캡처 기능 자체를 켜고 끄는 마스터 스위치
    private Boolean enableCapture=true;

    //초당 처리할 수 있는 최대 패킷 수 (성능 제한)
    private Integer maxPacketsPerSecond;


    public void changeCaptureConfig(String interfaceName, Integer captureTimeout, Integer bufferSize, Boolean enableCapture) {
        this.interfaceName = interfaceName;
        this.captureTimeout = captureTimeout;
        this.bufferSize = bufferSize;
        this.enableCapture = enableCapture;
        this.maxPacketsPerSecond = 1000;
    }
}