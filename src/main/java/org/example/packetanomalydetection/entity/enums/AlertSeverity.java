package org.example.packetanomalydetection.entity.enums;

public enum AlertSeverity {
    LOW("낮음", 1, "#28a745"),           // 녹색
    MEDIUM("보통", 2, "#ffc107"),        // 노란색
    HIGH("높음", 3, "#fd7e14"),          // 주황색
    CRITICAL("심각", 4, "#dc3545");      // 빨간색

    private final String koreanName;
    private final int priority;
    private final String colorCode;

    AlertSeverity(String koreanName, int priority, String colorCode) {
        this.koreanName = koreanName;
        this.priority = priority;
        this.colorCode = colorCode;
    }

    public String getKoreanName() { return koreanName; }
    public int getPriority() { return priority; }
    public String getColorCode() { return colorCode; }

    /**
     * 우선순위가 높은 순으로 정렬할 때 사용
     */
    public boolean isMoreCriticalThan(AlertSeverity other) {
        return this.priority > other.priority;
    }

    /**
     * 문자열로부터 Severity 찾기
     */
    public static AlertSeverity fromString(String severity) {
        for (AlertSeverity s : values()) {
            if (s.name().equalsIgnoreCase(severity) ||
                    s.koreanName.equals(severity)) {
                return s;
            }
        }
        throw new IllegalArgumentException("Unknown severity: " + severity);
    }
}
