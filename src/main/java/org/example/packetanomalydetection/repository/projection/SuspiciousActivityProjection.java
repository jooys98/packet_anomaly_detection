package org.example.packetanomalydetection.repository.projection;

import java.time.LocalDate;

public interface SuspiciousActivityProjection {
    LocalDate getDate();
    String getSourceIp();
    String getDestIp();
    String getProtocol();
    Long getCount();
    Double getAvgPacketSize();
}
