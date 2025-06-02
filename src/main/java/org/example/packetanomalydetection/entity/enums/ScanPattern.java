package org.example.packetanomalydetection.entity.enums;

import lombok.Getter;

@Getter
public enum ScanPattern {

    SEQUENTIAL("순차적 스캔"),
    COMMON_PORTS("일반 포트 스캔"),
    RANDOM("무작위 스캔"),
    INSUFFICIENT_DATA("데이터 부족");

    private final String description;

    ScanPattern(String description) {
        this.description = description;
    }

}