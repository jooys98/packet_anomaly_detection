package org.example.packetanomalydetection.entity;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.example.packetanomalydetection.entity.enums.CaptureMode;
import org.example.packetanomalydetection.entity.enums.CaptureStatus;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Entity
@Table(name = "capture_statistics")
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CaptureStatistics {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 세션 식별
    @Column(name = "session_id", unique = true, nullable = false)
    private String sessionId;  // UUID로 생성

    // 캡처 모드
    @Enumerated(EnumType.STRING)
    @Column(name = "capture_mode", nullable = false)
    private CaptureMode captureMode;

    // 기본 통계
    @Column(name = "total_packets", nullable = false)
    private Long totalPackets;

    @Column(name = "average_pps")
    private Double averagePacketsPerSecond;

    @Column(name = "peak_pps")
    private Double peakPacketsPerSecond;

    // 시간 정보
    @Column(name = "capture_start_time")
    private LocalDateTime captureStartTime;

    @Column(name = "capture_end_time")
    private LocalDateTime captureEndTime;


    @Column(name = "running_time_seconds")
    private Long runningTimeSeconds;

    // 상태 정보
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private CaptureStatus status;

    @Column(name = "network_interface", length = 100)
    private String networkInterface;


    public static CaptureStatistics from(String currentSessionId, LocalDateTime captureStartTime, CaptureMode mode, String networkInterface) {
        return CaptureStatistics.builder()
                .sessionId(currentSessionId)
                .captureMode(mode)
                .status(CaptureStatus.STARTING)
                .captureStartTime(captureStartTime)
                .totalPackets(0L)
                .averagePacketsPerSecond(0.0)
                .peakPacketsPerSecond(0.0)
                .networkInterface(networkInterface)
                .runningTimeSeconds(0L)
                .build();
    }

    public void updateStatus(CaptureStatus newStatus) {
        this.status = newStatus;
    }


    public void updateStatistics(LocalDateTime endTime, Long totalPackets,Long runningTimeSeconds,
    double averagePacketsPerSecond, Double peakPacketsPerSecond) {
        this.totalPackets = totalPackets;
        this.runningTimeSeconds = runningTimeSeconds;
        this.averagePacketsPerSecond = averagePacketsPerSecond;
        this.peakPacketsPerSecond = peakPacketsPerSecond;
        this.captureStartTime = LocalDateTime.now();
        this.captureEndTime = endTime;
        this.status = CaptureStatus.STARTING;
    }
}
