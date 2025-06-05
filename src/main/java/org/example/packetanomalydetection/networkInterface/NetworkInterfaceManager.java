package org.example.packetanomalydetection.networkInterface;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.config.PacketCaptureConfig;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 네트워크 인터페이스 관리 전담 클래스
 * 책임:
 * - 시스템 호환성 검사 (Apple Silicon, Pcap4J)
 * - 네트워크 인터페이스 검색 및 선택
 * - 인터페이스 유효성 검증
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class NetworkInterfaceManager {

    private final NetworkSystemValidator networkSystemValidator;
    private final PacketCaptureConfig captureConfig;

    @Getter
    private PcapNetworkInterface selectedInterface;



    /**
     * 네트워크 인터페이스 초기화
     */
    public void initializeInterface() throws PcapNativeException {
        // 모든 네트워크 인터페이스 조회
        List<PcapNetworkInterface> allInterfaces = Pcaps.findAllDevs();

        if (allInterfaces.isEmpty()) {
            throw new RuntimeException("사용 가능한 네트워크 인터페이스가 없습니다. 권한을 확인하세요.");
        }

        logAvailableInterfaces(allInterfaces);

        // 설정된 인터페이스 찾기
        String configuredInterfaceName = captureConfig.getInterfaceName();
        selectedInterface = findInterfaceByName(allInterfaces, configuredInterfaceName);

        if (selectedInterface == null) {
            log.warn("설정된 인터페이스 '{}' 를 찾을 수 없습니다.", configuredInterfaceName);

            // 자동으로 최적의 인터페이스 선택
            selectedInterface = networkSystemValidator.selectBestInterface(allInterfaces);

            if (selectedInterface == null) {
                log.error("적합한 네트워크 인터페이스를 찾을 수 없습니다");
                printInterfaceSelectionGuide(allInterfaces);
                throw new RuntimeException("사용 가능한 네트워크 인터페이스 없음");
            }

            log.info("자동 선택된 인터페이스: {}", selectedInterface.getName());
            log.info("application.yml에서 interface-name을 '{}'로 변경하는 것을 권장합니다",
                    selectedInterface.getName());
        }
    }

    /**
     * 사용 가능한 인터페이스 목록 로그 출력
     */
    private void logAvailableInterfaces(List<PcapNetworkInterface> interfaces) {
        log.info("발견된 네트워크 인터페이스 목록:");
        for (int i = 0; i < interfaces.size(); i++) {
            PcapNetworkInterface nif = interfaces.get(i);
            log.info("{}. {} - {} (활성: {}, 루프백: {})",
                    i + 1,
                    nif.getName(),
                    nif.getDescription() != null ? nif.getDescription() : "설명 없음",
                    nif.isUp() ? "예" : "아니오",
                    nif.isLoopBack() ? "예" : "아니오"
            );

            // IP 주소 정보 출력
            for (PcapAddress addr : nif.getAddresses()) {
                if (addr.getAddress() != null) {
                    log.info("     IP: {}", addr.getAddress().getHostAddress());
                }
            }
        }
    }

    /**
     * 이름으로 인터페이스 찾기
     */
    private PcapNetworkInterface findInterfaceByName(List<PcapNetworkInterface> interfaces,
                                                     String targetName) {
        return interfaces.stream()
                .filter(nif -> nif.getName().equals(targetName))
                .findFirst()
                .orElse(null);
    }


    /**
     * 인터페이스 선택 가이드 출력
     */
    private void printInterfaceSelectionGuide(List<PcapNetworkInterface> interfaces) {
        log.info("인터페이스 선택 가이드:");
        log.info("application.yml에서 다음 중 하나를 선택하세요:");

        for (PcapNetworkInterface nif : interfaces) {
            if (!nif.isLoopBack() && nif.isUp()) {
                log.info("monitoring:");
                log.info("  packet:");
                log.info("    interface-name: \"{}\"  # {}",
                        nif.getName(),
                        nif.getDescription() != null ? nif.getDescription() : "");
            }
        }
    }

    public String getSelectedInterfaceName() {
        return selectedInterface != null ? selectedInterface.getName() : null;
    }


}