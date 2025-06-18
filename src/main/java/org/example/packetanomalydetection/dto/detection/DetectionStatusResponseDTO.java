package org.example.packetanomalydetection.dto.detection;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class DetectionStatusResponseDTO {
    private Boolean autoDetectionEnabled;
    private int activeConnectionTrackers;
    private int activePortScanTrackers;
    private int activeTrafficTrackers;

}
