package org.example.packetanomalydetection;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class PacketAnomalyDetectionApplication {

    public static void main(String[] args) {
        SpringApplication.run(PacketAnomalyDetectionApplication.class, args);
        System.out.println("=================================");
        System.out.println("Network Security Monitor Starting...");
        System.out.println("=================================");
    }

}
