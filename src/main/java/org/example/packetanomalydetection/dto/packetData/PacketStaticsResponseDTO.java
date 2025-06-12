package org.example.packetanomalydetection.dto.packetData;

import lombok.*;
import org.example.packetanomalydetection.entity.CaptureStatistics;

import java.time.DayOfWeek;
import java.time.LocalDateTime;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class PacketStaticsResponseDTO {
    private String sessionId;
    private String captureMode;
    private Long runningTimeSeconds;
    private Long totalPackets;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private DayOfWeek dayOfWeek;


    public static PacketStaticsResponseDTO of(CaptureStatistics captureStatistics) {
        DayOfWeek dayOfWeek = captureStatistics.getCaptureEndTime().getDayOfWeek();

        return PacketStaticsResponseDTO.builder()
                .sessionId(captureStatistics.getSessionId())
                .captureMode(captureStatistics.getCaptureMode().toString())
                .runningTimeSeconds(captureStatistics.getRunningTimeSeconds())
                .startTime(captureStatistics.getCaptureStartTime())
                .endTime(captureStatistics.getCaptureEndTime())
                .dayOfWeek(dayOfWeek)
                .totalPackets(captureStatistics.getTotalPackets())
                .build();
    }
}
