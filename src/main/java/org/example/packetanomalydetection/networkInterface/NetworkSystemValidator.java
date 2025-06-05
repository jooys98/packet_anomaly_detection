package org.example.packetanomalydetection.networkInterface;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Slf4j
public class NetworkSystemValidator {

    /**
     * Apple Silicon Mac 여부 확인
     * Pcap4j와 호환성 문제로 시뮬레이션 모드로 설정하기 위한 로직
     */
    public boolean isAppleSiliconMac() {
        String osName = System.getProperty("os.name").toLowerCase();
        String osArch = System.getProperty("os.arch").toLowerCase();

        boolean isMac = osName.contains("mac");
        boolean isARM = osArch.contains("aarch64") || osArch.contains("arm");

        log.info("시스템 정보: OS={}, Architecture={}", osName, osArch);
        return isMac && isARM;
    }

    /**
     * Pcap4J 호환성 테스트
     */
    public boolean testPcap4jCompatibility() {
        try {
            // Pcap4J 라이브러리 로딩 테스트
            Class.forName("org.pcap4j.core.Pcaps");

            // 네트워크 인터페이스 조회 시도
            Pcaps.findAllDevs();

            log.info("Pcap4J 호환성 테스트 성공");
            return true;

        } catch (Exception e) {
            log.warn("Pcap4J 호환성 테스트 실패: {} - 시뮬레이션 모드 필요", e.getMessage());
            return false;
        }
    }

    /**
     * 최적의 네트워크 인터페이스 자동 선택
     * 선택 기준:
     * 1. 루프백이 아님 (실제 네트워크 트래픽)
     * 2. 활성화 상태
     * 3. IP 주소 할당됨
     * 4. 이더넷 또는 WiFi 인터페이스 우선
     */

    public PcapNetworkInterface selectBestInterface(List<PcapNetworkInterface> interfaces) {
        // 1순위: 이더넷/WiFi 인터페이스
        for (PcapNetworkInterface nif : interfaces) {
            if (isValidInterface(nif) && isPreferredInterfaceType(nif)) {
                return nif;
            }
        }

        // 2순위: 그냥 유효한 인터페이스
        for (PcapNetworkInterface nif : interfaces) {
            if (isValidInterface(nif)) {
                return nif;
            }
        }

        return null;
    }

    /**
     * 인터페이스 유효성 검사
     */
    public boolean isValidInterface(PcapNetworkInterface nif) {
        return !nif.isLoopBack() && nif.isUp() && hasValidIpAddress(nif);
    }

    /**
     * 유효한 IP 주소가 있는지 확인
     */
    private boolean hasValidIpAddress(PcapNetworkInterface nif) {
        for (PcapAddress addr : nif.getAddresses()) {
            if (addr.getAddress() != null) {
                String ip = addr.getAddress().getHostAddress();
                // 루프백 IP가 아닌 유효한 IP 주소
                if (!ip.equals("127.0.0.1") && !ip.equals("::1")) {
                    return true;
                }
            }
        }
        return false;
    }


    /**
     * 선호하는 인터페이스 타입인지 확인
     */
    private boolean isPreferredInterfaceType(PcapNetworkInterface nif) {
        String name = nif.getName().toLowerCase();
        return name.contains("eth") || name.contains("en") ||
                name.contains("wlan") || name.contains("wi-fi") ||
                name.contains("ethernet");
    }


}
