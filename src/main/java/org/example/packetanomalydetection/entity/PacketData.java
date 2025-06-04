package org.example.packetanomalydetection.entity;


import jakarta.persistence.*;
import lombok.*;
import org.pcap4j.packet.Packet;

import java.time.LocalDateTime;

@Entity
@Table(name = "packet_data")
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor

/**
 **실제 네트워크에서 캡처한 패킷의 기본 정보를 저장하는 엔티티
 **/

public class PacketData {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    //송신지 ip
    @Column(name = "source_ip", nullable = false, length = 45)
    private String sourceIp;

    //목적지 ip
    @Column(name = "dest_ip", nullable = false, length = 45)
    private String destIp;

    //송신지 포트번호
    @Column(name = "source_port")
    private Integer sourcePort;

    //목적지 포트번호
    @Column(name = "dest_port")
    private Integer destPort;

    //사용된 프로토콜
    @Column(name = "protocol", length = 10)
    private String protocol;

    //패킷크기(헤더 + 데이터)
    @Column(name = "packet_size")
    private Integer packetSize;


    //패킷이 캡처된 시간
    @Column(name = "timestamp")
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();

    //패킷에서 헤더를 제외한 순수 데이터 부분의 크기
    @Column(name = "payload_length")
    private Integer payloadLength;


    //TCP 의 flag 저장 (SYN,ACK,FIN 등 .. )
    @Column(name = "flags", length = 20)
    private String flags;

    /**
     * 패킷이 의심스러운지 간단히 판단하는 메서드
     * @return 의심스러운 패킷이면 true
     */
    public boolean isSuspicious() {
        // 대용량 패킷
        if (packetSize != null && packetSize > 1500) return true;
        // 시스템 포트 사용
        if (sourcePort != null && (sourcePort < 1024 && sourcePort != 80 && sourcePort != 443)) return true;
        return false;


    }










    // 의심스러운 패턴 탐지 예시
//    public boolean isSuspiciousPayload(PacketData packet) {
//        // 1. 페이로드가 비정상적으로 큰 경우 (데이터 유출 의심)
//        if (packet.getPayloadLength() > 8000) {
//            return true; // DDoS나 데이터 유출 공격 가능성
//        }
//
//        // 2. 페이로드가 0인데 계속 패킷을 보내는 경우
//        if (packet.getPayloadLength() == 0 && isFrequentSender(packet.getSourceIp())) {
//            return true; // 포트 스캔이나 핑 플러드 가능성
//        }
//
//        return false;
//    }
}
