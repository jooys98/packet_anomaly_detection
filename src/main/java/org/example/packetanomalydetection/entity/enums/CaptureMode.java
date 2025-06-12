package org.example.packetanomalydetection.entity.enums;

public enum CaptureMode {
    REAL_CAPTURE("실제 캡처"),
    SIMULATION("시뮬레이션");

    private final String description;
    CaptureMode(String description) { this.description = description; }
    public String getDescription() { return description; }
}

