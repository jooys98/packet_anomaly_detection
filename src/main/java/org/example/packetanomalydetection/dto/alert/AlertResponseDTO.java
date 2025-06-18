package org.example.packetanomalydetection.dto.alert;

import lombok.*;
import org.example.packetanomalydetection.entity.Alert;

import java.time.LocalDateTime;


@AllArgsConstructor
@NoArgsConstructor
@Getter
@ToString
@Builder
public class AlertResponseDTO {

    private Long id;
    private String alertType;
    private String description;
    private String severity;
    private String sourceIp;
    private String destIp;
    private Integer affectedPort;
    private LocalDateTime timestamp;
    private Boolean resolved;
    private LocalDateTime resolvedAt;
    private String resolvedBy;


    public static AlertResponseDTO from(Alert alert) {
        return AlertResponseDTO.builder()
                .id(alert.getId())
                .alertType(alert.getAlertType())
                .description(alert.getDescription())
                .sourceIp(alert.getSourceIp())
                .severity(alert.getSeverity().toString())
                .destIp(alert.getDestIp())
                .affectedPort(alert.getAffectedPort())
                .timestamp(alert.getTimestamp())
                .resolved(alert.getResolved())
                .resolvedAt(alert.getResolvedAt())
                .resolvedBy(alert.getResolvedBy())
                .build();
    }
}
