package org.example.packetanomalydetection.entity.enums;

import lombok.Getter;

@Getter
public enum CaptureStatus {

    STARTING("시작 중"),
    ACTIVE("활성"),
    STOPPED("중지됨"),
    ERROR("오류");

    private final String description;
    CaptureStatus(String description) { this.description = description; }
}

