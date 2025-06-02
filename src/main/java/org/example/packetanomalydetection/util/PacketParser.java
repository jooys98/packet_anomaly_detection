package org.example.packetanomalydetection.util;

import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.entity.PacketData;
import org.pcap4j.packet.*;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * 패킷 파싱 전담 유틸리티 클래스
 *
 * 책임:
 * - 실제 네트워크 패킷에서 헤더 정보 추출
 * - IP, 포트, 프로토콜, 플래그 등 정보 파싱
 * - 페이로드 크기 계산
 */
@Component
@Slf4j
public class PacketParser {

    /**
     * 실제 네트워크 패킷 파싱
     *
     * 패킷의 헤더 정보를 추출해서 PacketData 객체로 변환
     */
    public PacketData parseNetworkPacket(Packet packet) {
        try {
            // 이더넷 프레임 확인
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            if (ethernetPacket == null) {
                return null; // 이더넷 패킷이 아니면 무시
            }

            // IPv4 패킷 확인 및 파싱
            IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
            if (ipv4Packet == null) {
                // IPv6 패킷은 일단 무시 (필요시 나중에 추가)
                return null;
            }

            // IP 헤더에서 기본 정보 추출
            IpV4Packet.IpV4Header ipHeader = ipv4Packet.getHeader();
            String sourceIp = ipHeader.getSrcAddr().getHostAddress();
            String destIp = ipHeader.getDstAddr().getHostAddress();
            String protocol = ipHeader.getProtocol().name();

            // 포트 정보 및 플래그 추출
            PortAndFlagInfo portInfo = extractPortAndFlags(packet, protocol);

            // 패킷 크기 정보 계산
            int totalLength = packet.length();
            int payloadLength = calculatePayloadLength(packet, ipv4Packet);

            // PacketData 객체 생성
            return PacketData.builder()
                    .sourceIp(sourceIp)
                    .destIp(destIp)
                    .sourcePort(portInfo.sourcePort)
                    .destPort(portInfo.destPort)
                    .protocol(protocol)
                    .packetSize(totalLength)
                    .payloadLength(payloadLength)
                    .flags(portInfo.flags)
                    .timestamp(LocalDateTime.now())
                    .build();

        } catch (Exception e) {
            log.debug("패킷 파싱 중 오류 (무시): {}", e.getMessage());
            return null;
        }
    }

    /**
     * 포트 정보 및 플래그 추출 (TCP/UDP별 처리)
     */
    private PortAndFlagInfo extractPortAndFlags(Packet packet, String protocol) {
        PortAndFlagInfo info = new PortAndFlagInfo();

        if ("TCP".equals(protocol)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            if (tcpPacket != null) {
                TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                info.sourcePort = tcpHeader.getSrcPort().valueAsInt();
                info.destPort = tcpHeader.getDstPort().valueAsInt();
                info.flags = extractTcpFlags(tcpHeader);
            }

        } else if ("UDP".equals(protocol)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket != null) {
                UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                info.sourcePort = udpHeader.getSrcPort().valueAsInt();
                info.destPort = udpHeader.getDstPort().valueAsInt();
                info.flags = ""; // UDP에는 플래그 없음
            }
        }

        return info;
    }

    /**
     * TCP 플래그 추출 (SYN, ACK, FIN 등)
     */
    private String extractTcpFlags(TcpPacket.TcpHeader tcpHeader) {
        List<String> flagList = new ArrayList<>();

        if (tcpHeader.getSyn()) flagList.add("SYN");
        if (tcpHeader.getAck()) flagList.add("ACK");
        if (tcpHeader.getFin()) flagList.add("FIN");
        if (tcpHeader.getRst()) flagList.add("RST");
        if (tcpHeader.getPsh()) flagList.add("PSH");
        if (tcpHeader.getUrg()) flagList.add("URG");

        return String.join(",", flagList);
    }

    /**
     * 페이로드 길이 계산 (헤더 제외한 실제 데이터 크기)
     */
    private int calculatePayloadLength(Packet packet, IpV4Packet ipv4Packet) {
        try {
            int totalLength = packet.length();

            // IP 헤더 크기
            int ipHeaderLength = ipv4Packet.getHeader().getIhlAsInt() * 4;

            // TCP/UDP 헤더 크기
            int transportHeaderLength = 0;
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            UdpPacket udpPacket = packet.get(UdpPacket.class);

            if (tcpPacket != null) {
                transportHeaderLength = tcpPacket.getHeader().getDataOffsetAsInt() * 4;
            } else if (udpPacket != null) {
                transportHeaderLength = 8;// UDP 헤더는 8바이트 고정
            }

            return Math.max(0, totalLength - ipHeaderLength - transportHeaderLength);

        } catch (Exception e) {
            log.debug("페이로드 길이 계산 실패: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * IPv6 패킷 파싱 (향후 확장용)
     */
    public PacketData parseIpv6Packet(Packet packet) {
        // TODO: IPv6 패킷 파싱 로직 구현
        // 현재는 IPv4만 지원하므로 null 반환
        return null;
    }

    /**
     * 포트 및 플래그 정보를 담는 내부 클래스
     */
    private static class PortAndFlagInfo {
        Integer sourcePort;
        Integer destPort;
        String flags = "";
    }
}