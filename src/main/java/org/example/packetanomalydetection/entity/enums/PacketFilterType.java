package org.example.packetanomalydetection.entity.enums;


import lombok.Getter;

@Getter
public enum PacketFilterType {

    ALL("모든 패킷", ""),
    WEB_TRAFFIC("웹 트래픽만", "(port 80 or port 443)"),
    DNS_TRAFFIC("DNS 트래픽만", "port 53"),
    SSH_TRAFFIC("SSH 트래픽만", "port 22"),
    EMAIL_TRAFFIC("이메일 트래픽", "(port 25 or port 110 or port 143 or port 993 or port 995)"),
    TCP_ONLY("TCP만", "tcp"),
    UDP_ONLY("UDP만", "udp"),
    NO_INTERNAL("내부 네트워크 제외", "not net 192.168.0.0/16 and not net 10.0.0.0/8"),
    SUSPICIOUS_PORTS("의심스러운 포트", "(port 22 or port 23 or port 3389 or port 21)"),
    CUSTOM("사용자 정의", "");

    private final String description;
    private final String filterExpression;

    PacketFilterType(String description, String filterExpression) {
        this.description = description;
        this.filterExpression = filterExpression;
    }

}
