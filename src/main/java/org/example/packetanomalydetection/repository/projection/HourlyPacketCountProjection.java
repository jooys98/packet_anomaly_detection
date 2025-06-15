package org.example.packetanomalydetection.repository.projection;

import java.time.LocalDate;

public interface HourlyPacketCountProjection {
    LocalDate getDate();
    Integer getHour();
    Long getCount();
}
