package org.example.packetanomalydetection.dto.packetData;

import lombok.*;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@ToString
@Builder
public class HourlyPacketCountResponseDTO {
    private Integer hour;
    private Long count;

    public static HourlyPacketCountResponseDTO from(Object[] row) {
        return HourlyPacketCountResponseDTO.builder()
                .hour((Integer) row[0])
                .count((Long) row[1])
                .build();
    }
    }
