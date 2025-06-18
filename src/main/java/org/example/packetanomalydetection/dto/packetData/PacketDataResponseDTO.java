package org.example.packetanomalydetection.dto.packetData;

import lombok.*;
import org.example.packetanomalydetection.entity.PacketData;

import java.time.LocalDateTime;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class PacketDataResponseDTO {
    private Long id;
    private String sourceIp;
    private String destIp;
    private Integer sourcePort;
    private Integer destPort;
    private String protocol;
    private Integer packetSize;
    private LocalDateTime timestamp;
    private Integer payloadLength;
    private String flags;


    public static PacketDataResponseDTO from(PacketData packet) {
        return PacketDataResponseDTO.builder()
                .id(packet.getId())
                .sourceIp(packet.getSourceIp())
                .destIp(packet.getDestIp())
                .sourcePort(packet.getSourcePort())
                .destIp(packet.getDestIp())
                .protocol(packet.getProtocol())
                .packetSize(packet.getPacketSize())
                .timestamp(packet.getTimestamp())
                .payloadLength(packet.getPayloadLength())
                .flags(packet.getFlags())
                .build();

    }
}
