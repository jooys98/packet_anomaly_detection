package org.example.packetanomalydetection.unit;


import org.example.packetanomalydetection.dto.alert.AlertResponseDTO;
import org.example.packetanomalydetection.dto.alert.AlertStatisticsResponseDTO;
import org.example.packetanomalydetection.entity.Alert;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.example.packetanomalydetection.repository.AlertRepository;
import org.example.packetanomalydetection.service.alert.AlertQueryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AlertQueryServiceTest {

    @InjectMocks
    private AlertQueryService alertQueryService;

    @Mock
    private AlertRepository alertRepository;

    // 각 테스트 메서드 실행 전에 Mock 객체 초기화
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("활성 알림 조회 시 해결되지 않은 알림 목록을 반환해야 한다")
    void getActiveAlerts_shouldReturnUnresolvedAlerts() {
        // GIVEN (준비)
        // Mock Alert 객체 생성
        Alert activeAlert1 = Alert.builder()
                .id(1L).alertType("MULTIPLE_FAILED_ATTEMPTS").severity(AlertSeverity.HIGH)
                .timestamp(LocalDateTime.now().minusHours(1)).resolved(false).build();
        Alert activeAlert2 = Alert.builder()
                .id(2L).alertType("LARGE_PACKET").severity(AlertSeverity.CRITICAL)
                .timestamp(LocalDateTime.now().minusMinutes(30)).resolved(false).build();
        Alert resolvedAlert = Alert.builder() // 해결된 알림
                .id(3L).alertType("SUSPICIOUS_CONNECTION").severity(AlertSeverity.MEDIUM)
                .timestamp(LocalDateTime.now().minusDays(1)).resolved(true).resolvedAt(LocalDateTime.now()).resolvedBy("마라돼지").build();


        // alertRepository.findByResolvedFalseOrderByTimestampDesc() 호출 시 mockAlerts 중 resolved=false인 것만 반환하도록 Stubbing
        when(alertRepository.findByResolvedFalseOrderByTimestampDesc())
                .thenReturn(Arrays.asList(activeAlert1, activeAlert2));

        // WHEN (실행)
        List<AlertResponseDTO> result = alertQueryService.getActiveAlerts();

        // THEN (검증)
        // 1. alertRepository의 메서드가 정확히 한 번 호출되었는지 확인 (행위 검증)
        verify(alertRepository, times(1)).findByResolvedFalseOrderByTimestampDesc();
        verifyNoMoreInteractions(alertRepository); // 다른 메서드 호출은 없는지 확인


        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals(activeAlert1.getId(), result.get(0).getId());
        assertEquals(activeAlert2.getId(), result.get(1).getId());
        assertEquals(resolvedAlert.getId(), result.get(2).getId());
        assertFalse(result.get(0).getResolved());
        assertFalse(result.get(1).getResolved());

    }

    @Test
    @DisplayName("활성 알림이 없을 때 빈 목록을 반환해야 한다")
    void getActiveAlerts_shouldReturnEmptyList_whenNoActiveAlerts() {
        // GIVEN
        when(alertRepository.findByResolvedFalseOrderByTimestampDesc())
                .thenReturn(Collections.emptyList());

        // WHEN
        List<AlertResponseDTO> result = alertQueryService.getActiveAlerts();

        // THEN
        verify(alertRepository, times(1)).findByResolvedFalseOrderByTimestampDesc();
        verifyNoMoreInteractions(alertRepository);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("심각도별 알림 조회 시 해당 심각도의 알림 목록을 반환해야 한다")
    void getAlertsBySeverity_shouldReturnAlertsOfGivenSeverity() {
        // GIVEN
        int priority = 1; // CRITICAL (AlertSeverity.CRITICAL)
        AlertSeverity severity = AlertSeverity.CRITICAL;

        Alert criticalAlert1 = Alert.builder()
                .id(1L).alertType("DoS").severity(AlertSeverity.CRITICAL)
                .timestamp(LocalDateTime.now()).build();
        Alert criticalAlert2 = Alert.builder()
                .id(2L).alertType("Malware").severity(AlertSeverity.CRITICAL)
                .timestamp(LocalDateTime.now().minusHours(1)).build();
        Alert highAlert = Alert.builder() // 다른 심각도의 알림은 제외되어야 함
                .id(3L).alertType("Login Fail").severity(AlertSeverity.HIGH)
                .timestamp(LocalDateTime.now().minusDays(1)).build();

        when(alertRepository.findBySeverityOrderByTimestampDesc(severity))
                .thenReturn(Arrays.asList(criticalAlert1, criticalAlert2));

        // WHEN
        List<AlertResponseDTO> result = alertQueryService.getAlertsBySeverity(priority);

        // THEN
        verify(alertRepository, times(1)).findBySeverityOrderByTimestampDesc(severity);
        verifyNoMoreInteractions(alertRepository);
        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals(criticalAlert1.getId(), result.get(0).getId());
        assertEquals(criticalAlert2.getId(), result.get(1).getId());
        assertEquals(highAlert.getId(), result.get(2).getId());
        assertEquals(AlertSeverity.CRITICAL.name(), result.get(0).getSeverity());
    }

    @Test
    @DisplayName("유효하지 않은 심각도 우선순위 입력 시 적절히 처리해야 한다 (예: Exception 발생 또는 빈 목록)")
    void getAlertsBySeverity_shouldHandleInvalidPriority() {
        // GIVEN
        int invalidPriority = 99; // 존재하지 않는 우선순위

        // AlertSeverity.fromPriority()에서 예외가 발생하거나,
        // 아니면 AlertSeverity.fromPriority()가 기본값 또는 null을 반환하여 Repository 호출이 안 되도록 예상
        // 여기서는 AlertSeverity.fromPriority()가 IllegalArgumentException을 던진다고 가정
        // (AlertSeverity.java의 fromPriority 메서드 구현에 따라 달라짐)

        // WHEN & THEN
        // 예외 발생을 검증하는 경우:
        assertThrows(IllegalArgumentException.class, () -> {
            alertQueryService.getAlertsBySeverity(invalidPriority);
        });

        // Repository 메서드가 호출되지 않았음을 검증 (fromPriority에서 예외가 발생했으므로)
        verify(alertRepository, never()).findBySeverityOrderByTimestampDesc(any());
        verifyNoMoreInteractions(alertRepository);
    }


    @Test
    @DisplayName("최근 알림 조회 시 상위 50개 알림을 최신순으로 반환해야 한다")
    void getRecentAlerts_shouldReturnTop50AlertsOrderedByTimestampDesc() {
        // GIVEN
        // 50개 이상의 가짜 알림을 만들고, 상위 50개만 반환되도록 Stubbing
        List<Alert> fiftyAlerts = Arrays.asList(
                Alert.builder().id(1L).timestamp(LocalDateTime.now()).build(),
                Alert.builder().id(2L).timestamp(LocalDateTime.now().minusMinutes(1)).build()
                // ... 50개 알림 생성 (예시를 위해 2개만)
        );
        when(alertRepository.findTop50ByOrderByTimestampDesc()).thenReturn(fiftyAlerts);

        // WHEN
        List<AlertResponseDTO> result = alertQueryService.getRecentAlerts();

        // THEN
        verify(alertRepository, times(1)).findTop50ByOrderByTimestampDesc();
        verifyNoMoreInteractions(alertRepository);
        assertNotNull(result);
        assertEquals(50, result.size()); // 실제 50개라고 가정
        // 추가적으로 정렬 순서나 내용 검증
        assertEquals(1L, result.get(0).getId());
    }


    @Test
    @DisplayName("특정 IP 관련 알림 조회 시 해당 IP가 Source 또는 Destination인 알림을 반환해야 한다")
    void getAlertsByIp_shouldReturnAlertsRelatedToGivenIp() {
        // GIVEN
        String targetIp = "192.168.1.100";
        Alert alert1 = Alert.builder().id(1L).sourceIp(targetIp).destIp("10.0.0.1").build();
        Alert alert2 = Alert.builder().id(2L).sourceIp("172.16.0.5").destIp(targetIp).build();
        Alert alert3 = Alert.builder().id(3L).sourceIp("203.0.113.1").destIp("10.0.0.1").build(); // 제외되어야 함

        when(alertRepository.findBySourceIpOrDestIpOrderByTimestampDesc(targetIp, targetIp))
                .thenReturn(Arrays.asList(alert1, alert2));

        // WHEN
        List<AlertResponseDTO> result = alertQueryService.getAlertsByIp(targetIp);

        // THEN
        verify(alertRepository, times(1)).findBySourceIpOrDestIpOrderByTimestampDesc(targetIp, targetIp);
        verifyNoMoreInteractions(alertRepository);
        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals(alert1.getId(), result.get(0).getId());
        assertEquals(alert2.getId(), result.get(1).getId());
    }

    @Test
    @DisplayName("알림 통계 조회 시 올바른 통계 데이터를 반환해야 한다")
    void getAlertStatistics_shouldReturnCorrectStatistics() {
        // GIVEN
        long totalAlertsCount = 100L;
        long activeAlertsCount = 10L;

        // 오늘의 알림 (LocalDateTime.now()를 기준으로 Stubbing)
        LocalDateTime today = LocalDateTime.now();
        LocalDateTime todayStart = today.toLocalDate().atStartOfDay();
        LocalDate date = LocalDate.now();

        Alert todayCritical = Alert.builder().id(1L).alertType("Crit").severity(AlertSeverity.CRITICAL).timestamp(today.minusMinutes(10)).build();
        Alert todayHigh = Alert.builder().id(2L).alertType("High").severity(AlertSeverity.HIGH).timestamp(today.minusMinutes(20)).build();
        Alert todayHigh2 = Alert.builder().id(3L).alertType("High").severity(AlertSeverity.HIGH).timestamp(today.minusMinutes(30)).build();
        Alert todayMedium = Alert.builder().id(4L).alertType("Med").severity(AlertSeverity.MEDIUM).timestamp(today.minusMinutes(40)).build();
        List<Alert> alertsToday = Arrays.asList(todayCritical, todayHigh, todayHigh2, todayMedium);

        when(alertRepository.count()).thenReturn(totalAlertsCount);
        when(alertRepository.countActiveAlerts()).thenReturn(activeAlertsCount);
        when(alertRepository.findByTimestampBetweenOrderByTimestampDesc(eq(todayStart), any(LocalDateTime.class)))
                .thenReturn(alertsToday);

        // WHEN
        AlertStatisticsResponseDTO result = alertQueryService.getAlertStatistics(date);

        // THEN
        verify(alertRepository, times(1)).count();
        verify(alertRepository, times(1)).countActiveAlerts();
        verify(alertRepository, times(1)).findByTimestampBetweenOrderByTimestampDesc(eq(todayStart), any(LocalDateTime.class));
        verifyNoMoreInteractions(alertRepository);

        assertNotNull(result);
        assertEquals(totalAlertsCount, result.getTotalAlerts());
        assertEquals(activeAlertsCount, result.getActiveAlerts());


        // 심각도별 분포 검증
        assertEquals(1L, result.getSeverityDistribution().getCritical());
        assertEquals(2L, result.getSeverityDistribution().getHigh());
        assertEquals(1L, result.getSeverityDistribution().getMedium());
        assertEquals(0L, result.getSeverityDistribution().getLow());

        // 타입별 분포 검증
        assertEquals(1L, result.getTypeDistribution().get("Crit"));
        assertEquals(2L, result.getTypeDistribution().get("High"));
        assertEquals(1L, result.getTypeDistribution().get("Med"));
    }

    @Test
    @DisplayName("알림 통계 조회 시 오늘 알림이 없으면 0으로 올바르게 처리해야 한다")
    void getAlertStatistics_shouldHandleNoTodayAlerts() {
        // GIVEN
        long totalAlertsCount = 50L;
        long activeAlertsCount = 5L;
        LocalDate date = LocalDate.now();
        LocalDateTime today = LocalDateTime.now();
        LocalDateTime todayStart = today.toLocalDate().atStartOfDay();

        when(alertRepository.count()).thenReturn(totalAlertsCount);
        when(alertRepository.countActiveAlerts()).thenReturn(activeAlertsCount);
        when(alertRepository.findByTimestampBetweenOrderByTimestampDesc(eq(todayStart), any(LocalDateTime.class)))
                .thenReturn(Collections.emptyList()); // 오늘 알림이 없음

        // WHEN
        AlertStatisticsResponseDTO result = alertQueryService.getAlertStatistics(date);

        // THEN
        verify(alertRepository, times(1)).count();
        verify(alertRepository, times(1)).countActiveAlerts();
        verify(alertRepository, times(1)).findByTimestampBetweenOrderByTimestampDesc(eq(todayStart), any(LocalDateTime.class));
        verifyNoMoreInteractions(alertRepository);

        assertNotNull(result);
        assertEquals(totalAlertsCount, result.getTotalAlerts());
        assertEquals(activeAlertsCount, result.getActiveAlerts());
        assertEquals(0, result.getTotalAlerts()); // 0으로 검증
        assertEquals(0L, result.getSeverityDistribution().getCritical()); // 모두 0
        // ... 다른 심각도 및 타입 분포도 0으로 검증
    }

    @Test
    @DisplayName("알림 해결 시 알림 상태가 '해결됨'으로 업데이트되어야 하며 true를 반환해야 한다")
    void resolveAlert_shouldMarkAlertAsResolvedAndReturnTrue() {
        // GIVEN
        Long alertId = 1L;
        String resolvedBy = "tester";
        Alert alertToResolve = Alert.builder()
                .id(alertId).alertType("Test").resolved(false).build();

        // alertRepository.findById()가 알림을 찾도록 Stubbing
        when(alertRepository.findById(alertId)).thenReturn(Optional.of(alertToResolve));
        // alertRepository.save()가 호출될 때 아무것도 하지 않도록 (void 메서드이므로) 또는 인자로 받은 객체를 반환하도록 Stubbing
        when(alertRepository.save(any(Alert.class))).thenReturn(alertToResolve); // save()가 받은 Alert 객체를 반환한다고 가정

        // WHEN
        boolean result = alertQueryService.resolveAlert(alertId, resolvedBy);

        // THEN
        // 1. Repository 메서드 호출 검증
        verify(alertRepository, times(1)).findById(alertId);
        verify(alertRepository, times(1)).save(alertToResolve); // markAsResolved가 호출된 alertToResolve가 save되었는지 확인
        verifyNoMoreInteractions(alertRepository);

        // 2. 반환 값 및 Alert 객체 상태 검증
        assertTrue(result); // true가 반환되었는지
        assertTrue(alertToResolve.getResolved()); // Alert 객체의 resolved 상태가 true로 변경되었는지
        assertEquals(resolvedBy, alertToResolve.getResolvedBy()); // resolvedBy가 올바르게 설정되었는지
        assertNotNull(alertToResolve.getResolvedAt()); // 해결 시간이 설정되었는지
    }

    @Test
    @DisplayName("해결할 알림을 찾을 수 없을 때 false를 반환해야 한다")
    void resolveAlert_shouldReturnFalse_whenAlertNotFound() {
        // GIVEN
        Long nonExistentAlertId = 99L;
        String resolvedBy = "tester";

        // alertRepository.findById()가 Optional.empty()를 반환하도록 Stubbing
        when(alertRepository.findById(nonExistentAlertId)).thenReturn(Optional.empty());

        // WHEN
        boolean result = alertQueryService.resolveAlert(nonExistentAlertId, resolvedBy);

        // THEN
        verify(alertRepository, times(1)).findById(nonExistentAlertId);
        verify(alertRepository, never()).save(any(Alert.class)); // save는 호출되지 않아야 함
        verifyNoMoreInteractions(alertRepository);

        assertFalse(result); // false가 반환되었는지
    }

    // -----------------------------------------------------------------------------------------------------------------
    // ### 추가: DTO 및 Entity Helper Methods (테스트 데이터 생성 용이성을 위해) ###
    // Alert.java에 Builder 패턴과 필요한 Getter/Setter가 있다고 가정
    // AlertResponseDTO.from(Alert alert) 메서드가 Alert 객체를 DTO로 변환한다고 가정
    // AlertStatisticsResponseDTO.from() 및 AlertStatisticsResponseDTO.SeverityDistribution.from()이 있다고 가정
    // AlertSeverity.fromPriority(int priority) 메서드가 있다고 가정
    // -----------------------------------------------------------------------------------------------------------------

}
