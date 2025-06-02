package org.example.packetanomalydetection.config;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "monitoring.detection")
@Data
@NoArgsConstructor

/**
 * 위협 탐지 관련 기준을 설정하는 클래스
 **/

public class DetectionConfig {

    // 초당 1000개 이상의 패킷이 발생하면 "트래픽 급증" 알림 생성
    private Integer trafficSpikeThreshold = 1000;

    //동일한 ip에서 10개 이상의 서로 다른 포트에 연결 시도하면 "포트 스캔" 탐지
    private Integer portScanThreshold = 10;

    //1500바이트(실제 보편적인 MTU 값)보다 큰 패킷이 발견되면 "대용량 패킷" 알림
    private Integer largePacketThreshold = 1500;

    // 동일한 IP에서 5분 내에 50회 이상 연결 시도하면 "무차별 공격" 탐지
    private Integer connectionAttemptThreshold = 50;

    //위의 모든 탐지가 "5분간" 수집된 데이터를 기준으로 함
    private Integer timeWindowMinutes = 5;

    //자동 탐지 기능을 켜고 끌 수 있는 스위치
    private Boolean enableAutoDetection = true;
}
