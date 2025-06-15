package org.example.packetanomalydetection.performance;

import org.example.packetanomalydetection.dto.packetData.HourlyPacketCountResponseDTO;
import org.example.packetanomalydetection.repository.PacketDataRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.util.StopWatch;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import java.util.LongSummaryStatistics;


@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HourlyPacketQueryPerformanceTest {

    @Autowired
    private PacketDataRepository packetDataRepository;

    private static final LocalDate TEST_DATE = LocalDate.now().minusDays(1);

    @Test
    @Order(1)
    @DisplayName("Method 1: Interface Projection 성능 테스트")
    void testInterfaceProjectionPerformance() {
        System.out.println(" Interface Projection 테스트 시작");

        LocalDateTime start = TEST_DATE.atStartOfDay();
        LocalDateTime end = TEST_DATE.atTime(LocalTime.MAX);

        // Warm-up (JVM 최적화)
        for (int i = 0; i < 3; i++) {
            packetDataRepository.findHourlyPacketDistributionProjection(start, end);
        }

        // 실제 측정
        List<Long> executionTimes = new ArrayList<>();
        StopWatch stopWatch = new StopWatch();

        stopWatch.start();
        for (int i = 0; i < 50; i++) {
            long startTime = System.nanoTime();

            // Interface Projection만 테스트
            List<HourlyPacketCountResponseDTO> result =
                    packetDataRepository.findHourlyPacketDistributionProjection(start, end)
                            .stream().map(HourlyPacketCountResponseDTO::from).toList();


            // 검증
            Assertions.assertNotNull(result);
            if (!result.isEmpty()) {
                Assertions.assertNotNull(result.get(0).getHour());
                Assertions.assertNotNull(result.get(0).getCount());
                Assertions.assertNotNull(result.get(0).getDate());
            }

            long endTime = System.nanoTime();
            executionTimes.add(endTime - startTime);
        }
        stopWatch.stop();

        printPerformanceResults("Interface Projection", executionTimes, stopWatch.getTotalTimeMillis());
    }

    @Test
    @Order(2)
    @DisplayName("Method 2: Direct DTO Creation 성능 테스트")
    void testDirectDTOPerformance() {
        System.out.println(" Direct DTO Creation 테스트 시작");

        LocalDateTime start = TEST_DATE.atStartOfDay();
        LocalDateTime end = TEST_DATE.atTime(LocalTime.MAX);

        // Warm-up
        for (int i = 0; i < 3; i++) {
            packetDataRepository.findHourlyPacketDistributionDTO(start, end);
        }

        List<Long> executionTimes = new ArrayList<>();
        StopWatch stopWatch = new StopWatch();

        stopWatch.start();
        for (int i = 0; i < 50; i++) {
            long startTime = System.nanoTime();

            // Direct DTO Creation 방식 사용
            List<HourlyPacketCountResponseDTO> result =
                    packetDataRepository.findHourlyPacketDistributionDTO(start, end);

            // 검증
            Assertions.assertNotNull(result);
            if (!result.isEmpty()) {
                Assertions.assertNotNull(result.get(0).getHour());
                Assertions.assertNotNull(result.get(0).getCount());
            }

            long endTime = System.nanoTime();
            executionTimes.add(endTime - startTime);
        }
        stopWatch.stop();

        printPerformanceResults("Direct DTO Creation", executionTimes, stopWatch.getTotalTimeMillis());
    }


    @Test
    @Order(3)
    @DisplayName("성능 비교 및 분석")
    void performanceComparison() {
        System.out.println("성능 비교 분석");
        System.out.println("각 방법의 특징:");
        System.out.println("1. Interface Projection: JPA 네이티브 지원, 최소 오버헤드");
        System.out.println("2. Direct DTO Creation: 한 번에 완성된 객체, Repository-DTO 결합");
        System.out.println("3. Object[] + Service: 계층 분리, 변환 오버헤드");
        System.out.println("=====================================\n");
    }

    private void printPerformanceResults(String methodName, List<Long> executionTimes, long totalTime) {
        LongSummaryStatistics stats = executionTimes.stream()
                .mapToLong(Long::longValue)
                .summaryStatistics();

        System.out.printf("=== %s 성능 결과 ===\n", methodName);
        System.out.printf("총 실행 시간: %d ms\n", totalTime);
        System.out.printf("평균 실행 시간: %.2f ms\n", stats.getAverage() / 1_000_000.0);
        System.out.printf("최소 실행 시간: %.2f ms\n", stats.getMin() / 1_000_000.0);
        System.out.printf("최대 실행 시간: %.2f ms\n", stats.getMax() / 1_000_000.0);
        System.out.printf("실행 횟수: %d회\n", stats.getCount());
        System.out.println("===============================\n");
    }
}