package org.example.packetanomalydetection.entity;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;

import java.time.LocalDateTime;

@Entity
@Table(name = "alert")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder

/**
 * PacketData 를 분석해서 발견한 의심스러운 흔적을 기록하는 엔티티
 **/

public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    //어떤 종류의 위험인지 기록
    @Column(name = "alert_type", nullable = false, length = 50)
    private String alertType;

    //위험 설명 기록
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    //위험도 표기
    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    private AlertSeverity severity;

    //공격자 ip
    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    //피해자 ip
    @Column(name = "dest_ip", length = 45)
    private String destIp;

    //영향받은 포트
    @Column(name = "affected_port")
    private Integer affectedPort;

    //위험이 감지된 시간
    @Column(name = "timestamp")
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();

    //해결여부 - 기본 false
    @Column(name = "resolved")
    @Builder.Default
    private Boolean resolved = false;


    //해결 시간
    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    //해결한 담당자
    @Column(name = "resolved_by", length = 100)
    private String resolvedBy;


    /**
     * 알림을 해결된 상태로 마크
     *
     * @param resolvedBy 해결한 사람
     */
    public void markAsResolved(String resolvedBy) {
        this.resolved = true;
        this.resolvedAt = LocalDateTime.now();
        this.resolvedBy = resolvedBy;
    }

    public void addTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}
