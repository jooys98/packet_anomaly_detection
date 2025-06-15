package org.example.packetanomalydetection.dto.packetData;

import lombok.*;
import org.example.packetanomalydetection.repository.projection.ActiveSourceIpProtocolProjection;

import java.time.LocalDate;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class ActiveSourceIpResponseDTO {
    private String ip;
    private Long count;
    private String protocol;
    private LocalDate date;

    public static ActiveSourceIpResponseDTO of(ActiveSourceIpProtocolProjection activeSourceIpProjection) {
        return ActiveSourceIpResponseDTO.builder()
                .date(activeSourceIpProjection.getDate())
                .ip(activeSourceIpProjection.getIp())
                .count(activeSourceIpProjection.getCount())
                .protocol(activeSourceIpProjection.getProtocol())
                .build();
    }
}
