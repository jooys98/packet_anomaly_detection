package org.example.packetanomalydetection.dto.packetData;

import lombok.*;
import org.example.packetanomalydetection.repository.projection.SuspiciousActivityProjection;

import java.time.LocalDate;

@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class SuspiciousActivityResponseDTO {
    private LocalDate date;
    private String sourceIp;
    private String protocol;
    private Long packetCount;
    private Double avgPacketSize;
    private String riskLevel;
    private String suspiciousReason;

    public static SuspiciousActivityResponseDTO from(SuspiciousActivityProjection projection) {
        return SuspiciousActivityResponseDTO.builder()
                .date(projection.getDate())
                .sourceIp(projection.getSourceIp())
                .protocol(projection.getProtocol())
                .packetCount(projection.getCount())
                .avgPacketSize(Math.round(projection.getAvgPacketSize() * 100.0) / 100.0) // 소수점 2자리
                .riskLevel(calculateRiskLevel(projection.getCount(), projection.getAvgPacketSize()))
                .suspiciousReason(generateSuspiciousReason(projection))
                .build();
    }

    /**
     * 위험도 레벨 계산
     */
    private static String calculateRiskLevel(Long packetCount, Double avgPacketSize) {
        if (packetCount > 5000 || avgPacketSize > 1400) {
            return "CRITICAL";
        } else if (packetCount > 2000 || avgPacketSize > 1000) {
            return "HIGH";
        } else if (packetCount > 500 || avgPacketSize > 500) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }

    /**
     * 의심스러운 활동 이유 생성
     */
    private static String generateSuspiciousReason(SuspiciousActivityProjection projection) {
        String protocol = projection.getProtocol();
        Long count = projection.getCount();
        Double avgSize = projection.getAvgPacketSize();

        StringBuilder reason = new StringBuilder();
        reason.append(String.format("IP %s에서 %s 프로토콜로 ",
                projection.getSourceIp(), protocol));

        if (count > 5000) {
            reason.append("매우 높은 빈도의 패킷 전송 감지 (").append(count).append("개)");
        } else if (count > 2000) {
            reason.append("높은 빈도의 패킷 전송 감지 (").append(count).append("개)");
        } else {
            reason.append("중간 수준의 패킷 전송 감지 (").append(count).append("개)");
        }

        if (avgSize > 1400) {
            reason.append(", 비정상적으로 큰 패킷 크기 (평균 ").append(Math.round(avgSize)).append(" bytes)");
        } else if (avgSize > 1000) {
            reason.append(", 큰 패킷 크기 (평균 ").append(Math.round(avgSize)).append(" bytes)");
        }

        return reason.toString();
    }
}
