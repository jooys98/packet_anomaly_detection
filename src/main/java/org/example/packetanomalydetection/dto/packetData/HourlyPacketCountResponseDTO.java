package org.example.packetanomalydetection.dto.packetData;

import lombok.*;
import org.example.packetanomalydetection.repository.projection.HourlyPacketCountProjection;

import java.time.LocalDate;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@ToString
@Builder
public class HourlyPacketCountResponseDTO {
    private LocalDate date;
    private Integer hour;
    private Long count;

    public static HourlyPacketCountResponseDTO from(HourlyPacketCountProjection projection) {
        return HourlyPacketCountResponseDTO.builder()
                .date(projection.getDate())
                .hour(projection.getHour())
                .count(projection.getCount())
                .build();
    }


    }
