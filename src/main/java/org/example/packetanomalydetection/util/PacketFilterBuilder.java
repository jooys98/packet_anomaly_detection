package org.example.packetanomalydetection.util;

import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.config.PacketFilterConfig;
import org.example.packetanomalydetection.entity.enums.PacketFilterType;
import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 *  패킷 필터 생성기
 * 사용자 설정에 따라 Berkeley Packet Filter (BPF) 문법으로 필터 생성
 */
@Component
@Slf4j
public class PacketFilterBuilder {

    /**
     * 🎯 메인 필터 생성 메서드
     */
    public String buildFilter(PacketFilterConfig filterConfig) {

        if (!filterConfig.getEnableFilter()) {
            log.info("🔍 패킷 필터 비활성화 - 모든 패킷 캡처");
            return "";
        }

        String filterMode = filterConfig.getFilterMode();
        log.info("🔍 패킷 필터 모드: {}", filterMode);

        switch (filterMode.toUpperCase()) {
            case "BASIC":
                return buildBasicFilter(filterConfig);
            case "ADVANCED":
                return buildAdvancedFilter(filterConfig);
            case "CUSTOM":
                return buildCustomFilter(filterConfig);
            case "PRESET":
                return buildPresetFilter(filterConfig);
            default:
                log.warn("⚠️ 알 수 없는 필터 모드: {}, 기본 필터 사용", filterMode);
                return buildDefaultFilter();
        }
    }

    /**
     * 기본 필터 (IP 트래픽만)
     */
    private String buildBasicFilter(PacketFilterConfig filterConfig) {
        List<String> parts = new ArrayList<>();

        // 기본: IPv4 트래픽만
        parts.add("ip");

        log.info("✅ 기본 필터 생성: IPv4 트래픽만 캡처");
        return String.join(" and ", parts);
    }

    /**
     * 🔧 고급 필터 (프로토콜, 포트, 네트워크 제외 등)
     */
    private String buildAdvancedFilter(PacketFilterConfig filterConfig) {
        List<String> parts = new ArrayList<>();

        // 1. 기본 IP 필터
        parts.add("ip");

        // 2. 프로토콜 필터
        if (!filterConfig.getProtocols().isEmpty()) {
            String protocolFilter = filterConfig.getProtocols().stream()
                    .map(String::toLowerCase)
                    .collect(Collectors.joining(" or "));
            parts.add("(" + protocolFilter + ")");
            log.info("🌐 프로토콜 필터: {}", protocolFilter);
        }

        // 3. 포트 필터
        if (!filterConfig.getPorts().isEmpty()) {
            String portFilter = filterConfig.getPorts().stream()
                    .map(port -> "port " + port)
                    .collect(Collectors.joining(" or "));
            parts.add("(" + portFilter + ")");
            log.info(" 포트 필터: {}", portFilter);
        }

        // 4. 네트워크 제외 필터
        if (!filterConfig.getExcludeNetworks().isEmpty()) {
            for (String network : filterConfig.getExcludeNetworks()) {
                parts.add("not net " + network);
                log.info("네트워크 제외: {}", network);
            }
        }

        String finalFilter = String.join(" and ", parts);
        log.info("✅ 고급 필터 생성: {}", finalFilter);
        return finalFilter;
    }

    /**
     * 🎨 사용자 정의 필터
     */
    private String buildCustomFilter(PacketFilterConfig filterConfig) {
        String customFilter = filterConfig.getCustomFilter();

        if (customFilter == null || customFilter.trim().isEmpty()) {
            log.warn("⚠️ 사용자 정의 필터가 비어있음, 기본 필터 사용");
            return buildDefaultFilter();
        }

        // 🔒 보안: 위험한 필터 문법 체크
        if (isValidBpfFilter(customFilter)) {
            log.info("✅ 사용자 정의 필터: {}", customFilter);
            return customFilter;
        } else {
            log.error("❌ 유효하지 않은 필터 문법: {}", customFilter);
            return buildDefaultFilter();
        }
    }

    /**
     * 📋 프리셋 필터 (미리 정의된 필터들)
     */
    private String buildPresetFilter(PacketFilterConfig filterConfig) {
        // 설정에서 프리셋 타입을 가져와서 사용
        // 실제로는 별도 설정 필드가 필요하지만, 예시로 웹 트래픽 필터 사용
        return PacketFilterType.WEB_TRAFFIC.getFilterExpression();
    }

    /**
     * 🛡️ 기본 필터 (안전한 기본값)
     */
    private String buildDefaultFilter() {
        return "ip";
    }

    /**
     * 🔒 BPF 필터 문법 검증 (보안용)
     */
    private boolean isValidBpfFilter(String filter) {
        // 기본적인 BPF 문법 검증
        // 실제로는 더 정교한 검증이 필요

        // 위험한 키워드 체크
        String[] dangerousKeywords = {"exec", "system", "command", ";", "|", "&"};
        String lowerFilter = filter.toLowerCase();

        for (String keyword : dangerousKeywords) {
            if (lowerFilter.contains(keyword)) {
                log.warn("🚨 위험한 키워드 발견: {}", keyword);
                return false;
            }
        }

        // 길이 제한 (너무 긴 필터는 위험할 수 있음)
        if (filter.length() > 500) {
            log.warn("🚨 필터가 너무 김: {} characters", filter.length());
            return false;
        }

        return true;
    }

    /**
     * 📚 사용 가능한 필터 예시 출력
     */
    public void printFilterExamples() {
        log.info("📚 사용 가능한 패킷 필터 예시:");
        log.info("🔹 웹 트래픽만: (port 80 or port 443)");
        log.info("🔹 DNS 트래픽만: port 53");
        log.info("🔹 TCP만: tcp");
        log.info("🔹 UDP만: udp");
        log.info("🔹 SSH 트래픽: port 22");
        log.info("🔹 내부 네트워크 제외: not net 192.168.0.0/16");
        log.info("🔹 특정 IP만: host 8.8.8.8");
        log.info("🔹 복합 조건: tcp and port 80 and not host 127.0.0.1");
    }
}