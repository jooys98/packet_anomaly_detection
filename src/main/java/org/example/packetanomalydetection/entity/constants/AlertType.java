package org.example.packetanomalydetection.entity.constants;

import org.example.packetanomalydetection.entity.enums.AlertSeverity;


//알림의 타입을 정의해놓은 클래스
public final class AlertType {
    // 네트워크 관련 알림
    public static final String TRAFFIC_SPIKE = "TRAFFIC_SPIKE";
    public static final String PORT_SCAN = "PORT_SCAN";
    public static final String SYN_FLOOD = "SYN_FLOOD";
    public static final String DDOS_ATTACK = "DDOS_ATTACK";

    // 패킷 관련 알림
    public static final String LARGE_PACKET = "LARGE_PACKET";
    public static final String MALFORMED_PACKET = "MALFORMED_PACKET";
    public static final String SUSPICIOUS_PAYLOAD = "SUSPICIOUS_PAYLOAD";

    // 연결 관련 알림
    public static final String SUSPICIOUS_CONNECTION = "SUSPICIOUS_CONNECTION";
    public static final String MULTIPLE_FAILED_ATTEMPTS = "MULTIPLE_FAILED_ATTEMPTS";
    public static final String BRUTE_FORCE_ATTACK = "BRUTE_FORCE_ATTACK";

    // 시스템 관련 알림
    public static final String SYSTEM_OVERLOAD = "SYSTEM_OVERLOAD";
    public static final String CAPTURE_FAILURE = "CAPTURE_FAILURE";

    private AlertType() {
        throw new UnsupportedOperationException("상수 클래스는 인스턴스화할 수 없습니다.");
    }

    /**
     * 알림 타입별 기본 심각도 반환
     */
    public static AlertSeverity getDefaultSeverity(String alertType) {
        switch (alertType) {
            case DDOS_ATTACK:
            case SYN_FLOOD:
            case BRUTE_FORCE_ATTACK:
                return AlertSeverity.CRITICAL;

            case PORT_SCAN:
            case TRAFFIC_SPIKE:
            case SUSPICIOUS_CONNECTION:
                return AlertSeverity.HIGH;

            case LARGE_PACKET:
            case MULTIPLE_FAILED_ATTEMPTS:
            case MALFORMED_PACKET:
                return AlertSeverity.MEDIUM;

            case SUSPICIOUS_PAYLOAD:
            case SYSTEM_OVERLOAD:
                return AlertSeverity.LOW;

            default:
                return AlertSeverity.MEDIUM;
        }
    }

    /**
     * 알림 타입별 한글 설명 반환
     */
    public static String getKoreanDescription(String alertType) {
        switch (alertType) {
            case TRAFFIC_SPIKE: return "트래픽 급증";
            case PORT_SCAN: return "포트 스캔";
            case SYN_FLOOD: return "SYN 플러드 공격";
            case DDOS_ATTACK: return "DDoS 공격";
            case LARGE_PACKET: return "대용량 패킷";
            case MALFORMED_PACKET: return "비정상 패킷";
            case SUSPICIOUS_PAYLOAD: return "의심스러운 페이로드";
            case SUSPICIOUS_CONNECTION: return "의심스러운 연결";
            case MULTIPLE_FAILED_ATTEMPTS: return "다중 실패 시도";
            case BRUTE_FORCE_ATTACK: return "무차별 대입 공격";
            case SYSTEM_OVERLOAD: return "시스템 과부하";
            case CAPTURE_FAILURE: return "패킷 캡처 실패";
            default: return "알 수 없는 알림";
        }
    }

    /**
     * 모든 알림 타입 목록 반환
     */
    public static String[] getAllTypes() {
        return new String[] {
                TRAFFIC_SPIKE, PORT_SCAN, SYN_FLOOD, DDOS_ATTACK,
                LARGE_PACKET, MALFORMED_PACKET, SUSPICIOUS_PAYLOAD,
                SUSPICIOUS_CONNECTION, MULTIPLE_FAILED_ATTEMPTS, BRUTE_FORCE_ATTACK,
                SYSTEM_OVERLOAD, CAPTURE_FAILURE
        };
    }
}
