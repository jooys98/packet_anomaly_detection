package org.example.packetanomalydetection.dto.packetData;

import lombok.*;

import java.time.DayOfWeek;
import java.time.LocalDateTime;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class PacketStaticsResponseDTO {
    private Long totalPackets;
    private LocalDateTime lastTime;
    private DayOfWeek dayOfWeek;


    public static PacketStaticsResponseDTO of(LocalDateTime lastTime, Long totalPackets) {
        DayOfWeek dayOfWeek = lastTime.getDayOfWeek();

        return PacketStaticsResponseDTO.builder()
                .lastTime(lastTime)
                .dayOfWeek(dayOfWeek)
                .totalPackets(totalPackets)
                .build();
    }
}
