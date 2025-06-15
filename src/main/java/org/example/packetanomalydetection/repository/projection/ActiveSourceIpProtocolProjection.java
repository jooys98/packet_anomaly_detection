package org.example.packetanomalydetection.repository.projection;

import java.time.LocalDate;

public interface ActiveSourceIpProtocolProjection {
    String getIp();
    Long getCount();
    LocalDate getDate();
    String getProtocol();

}
