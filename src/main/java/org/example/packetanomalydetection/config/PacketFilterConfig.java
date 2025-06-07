package org.example.packetanomalydetection.config;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 패킷 필터링 전용 설정
 * 책임:
 * - 캡처할 패킷 유형 필터링
 * - 네트워크 트래픽 선별
 * - Berkeley Packet Filter (BPF) 규칙 관리
 */
@Component
@Data
@NoArgsConstructor
@Getter
public class PacketFilterConfig {

    /**
     * 패킷 필터 사용 여부
     * false: 모든 패킷 캡처 (성능 영향 있음)
     * true: 지정된 조건에 맞는 패킷만 캡처
     */
    private Boolean enableFilter = false;

    /**
     * 필터 모드
     * - BASIC: 기본 프로토콜/포트 필터링
     * - ADVANCED: 고급 조건부 필터링
     * - CUSTOM: 사용자 정의 BPF 필터
     */
    private String filterMode= "basic";

    /**
     * 캡처할 프로토콜 목록
     * 예: ["TCP", "UDP", "ICMP"]
     * 빈 리스트일 경우 모든 프로토콜 캡처
     */
    private List<String> protocols = new ArrayList<>();

    /**
     * 캡처할 포트 번호 목록
     * 예: [80, 443, 22, 3389]
     * 빈 리스트일 경우 모든 포트 캡처
     */
    private List<Integer> ports = new ArrayList<>();

    /**
     * 제외할 네트워크 대역 (CIDR 표기법)
     * 예: ["127.0.0.0/8", "10.0.0.0/8"]
     * 내부 트래픽 제외 시 유용
     */
    private List<String> excludeNetworks = new ArrayList<>();

    /**
     * 포함할 네트워크 대역 (CIDR 표기법)
     * 예: ["192.168.1.0/24"]
     * 특정 네트워크만 모니터링 시 사용
     */
    private List<String> includeNetworks = new ArrayList<>();

    /**
     * 사용자 정의 Berkeley Packet Filter (BPF) 표현식
     * 예: "tcp port 80 or udp port 53"
     * filterMode가 "CUSTOM"일 때 사용
     */
    private String customFilter = "";

    /**
     * 최소 패킷 크기 필터 (바이트)
     * 0보다 크면 해당 크기 이상의 패킷만 캡처
     */
    private Integer minPacketSize = 0;

    /**
     * 최대 패킷 크기 필터 (바이트)
     * 0보다 크면 해당 크기 이하의 패킷만 캡처
     */
    private Integer maxPacketSize = 0;

    public void changeFilterMode(Boolean enableFilter, String filterMode,
                                 List<String> protocols, List<Integer> ports,
                                 List<String> excludeNetworks, List<String> includeNetworks,
                                 String customFilter, Integer minPacketSize, Integer maxPacketSize
    ) {
        this.filterMode = filterMode;
        this.protocols = protocols;
        this.ports = ports;
        this.excludeNetworks = excludeNetworks;
        this.includeNetworks = includeNetworks;
        this.customFilter = customFilter;
        this.minPacketSize = minPacketSize;
        this.maxPacketSize = maxPacketSize;
        this.enableFilter = enableFilter;
    }


    /**
     * 필터 검증 메서드
     */
    public boolean isValidConfiguration() {
        if (!enableFilter) {
            return true; // 필터 비활성화시 항상 유효
        }

        // CUSTOM 모드에서 customFilter가 비어있으면 무효
        if ("CUSTOM".equals(filterMode) &&
                (customFilter == null || customFilter.trim().isEmpty())) {
            return false;
        }

        // 포트 범위 검증
        return ports.stream().allMatch(port -> port > 0 && port <= 65535);
    }

    /**
     * 필터가 활성화되어 있고 유효한지 확인
     */
    public boolean isActiveAndValid() {
        return enableFilter && isValidConfiguration();
    }
}