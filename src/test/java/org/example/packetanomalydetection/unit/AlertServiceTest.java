package org.example.packetanomalydetection.unit;

import org.example.packetanomalydetection.entity.Alert;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.example.packetanomalydetection.repository.AlertRepository;
import org.example.packetanomalydetection.service.alert.AlertNotificationService;
import org.example.packetanomalydetection.service.alert.AlertService;
import org.junit.jupiter.api.*;
import org.mockito.Mock;

import static org.mockito.Mockito.*;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import org.mockito.MockitoAnnotations;
import org.springframework.util.StopWatch;

class AlertServiceTest {

    private AlertService alertService;
    @Mock
    private AlertRepository alertRepository;
    @Mock
    private AlertNotificationService alertNotificationService;

    //테스트 실행 전 초기화 설정
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // 실제 AlertService 인스턴스를 생성하고 spy()로 포장
        // AlertService 의 생성자에 필요한 Mock 객체들을 전달

        alertService = spy(new AlertService(alertRepository, alertNotificationService));
    }

    @Test
    @DisplayName("유효하고 중복되지 않은 알림 생성 요청 시 모든 후처리 메서드가 호출되어야 한다")
    void sendAlert() {
        System.out.println("알람생성 및 검증 테스트 진행");

        StopWatch validatorTest = new StopWatch("Validator Independent Test");
        validatorTest.start();
        // GIVEN (준비)
        Alert alert = mock(Alert.class);

        //Alert 클래스의 Mock 객체 생성
        when(alert.getAlertType()).thenReturn("LARGE_PACKET");
        when(alert.getSeverity()).thenReturn(AlertSeverity.CRITICAL);
        when(alert.getDescription()).thenReturn("비정상적으로 큰 패킷 탐지: 8000 bytes (정상 범위: 1500 bytes 이하)\n" +
                "출발지: 172.16.0.50:8080 → 목적지: 192.168.1.100:80");
        when(alert.getSourceIp()).thenReturn("172.16.0.50");

        doReturn(true).when(alertService).isValidAlert(alert);

        when(alertNotificationService.isDuplicateAlert(alert)).thenReturn(false);
        when(alertRepository.save(alert)).thenReturn(alert);

        //WHEN (실행)
        alertService.createAlert(alert);
        // THEN (검증)


        //실제 메서드의 논리적 흐름과 일치시켜 verify 호출
        verify(alertNotificationService, times(1)).isDuplicateAlert(alert);
        verify(alertRepository, times(1)).save(alert);
        verify(alertNotificationService, times(1)).updateAlertStatistics(alert);
        verify(alertNotificationService, times(1)).processImmediateNotification(alert);
        verify(alertNotificationService, times(1)).updateDuplicatePreventionCache(alert);
        verifyNoMoreInteractions(alertNotificationService, alertRepository);

        validatorTest.stop();

        System.out.println("=== createAlert 테스트 결과 ===");
        System.out.printf("createAlert 실행: %dms\n",
                validatorTest.getTotalTimeMillis());

    }

    //유효성 검증 실패 시 시나리오
    @Test
    @DisplayName("유효하지 않은 알림 요청 시 후처리 메서드들이 호출되지 않아야 한다")
    void sendAlertNotification() {
        // GIVEN (준비)

        Alert invalidAlert = mock(Alert.class);
        // spy 로 감싸진 alertService 가 isValidAlert 를 호출할 때 false 를 반환하도록 Stubbing
        doReturn((false)).when(alertService).isValidAlert(invalidAlert);

        // WHEN (실행)
        alertService.createAlert(invalidAlert);

        verify(alertService, times(1)).isValidAlert(invalidAlert);
        // THEN (검증)
        // 유효성 검증 후처리 메서드들은 호출되지 않았음을 검증
        verify(alertNotificationService, never()).isDuplicateAlert(invalidAlert);
        verify(alertRepository, never()).save(any());
        verify(alertNotificationService, never()).updateDuplicatePreventionCache(invalidAlert);
        verify(alertNotificationService, never()).processImmediateNotification(invalidAlert);
        verify(alertNotificationService, never()).updateAlertStatistics(invalidAlert);
        verify(alertNotificationService, never()).setCriticalAlertsToday();

    }

    @Test
    @DisplayName("중복 알림 요청 시 저장 및 후처리 메서드들이 호출되지 않고 조기에 종료되어야 한다")
    void givenDuplicateAlert_whenCreateAlert_thenOnlyDuplicateCheckIsCalled() {
        // GIVEN (준비)
        Alert duplicateMockAlert = mock(Alert.class);
        // Mock Alert의 Getter Stubbing (isValidAlert가 true를 반환하도록)

        when(duplicateMockAlert.getAlertType()).thenReturn("MULTIPLE_FAILED_ATTEMPTS");
        when(duplicateMockAlert.getSeverity()).thenReturn(AlertSeverity.HIGH);
        when(duplicateMockAlert.getDescription()).thenReturn("브루트포스 공격 탐지\n" +
                "공격자 IP: 192.168.1.15\n" +
                "연결 시도: 50회 (5분간)\n" +
                "대상: 1.1.1.1:53");
        when(duplicateMockAlert.getSourceIp()).thenReturn("192.168.1.1"); // 중복 체크에 필요

        // AlertService (spy 객체)의 isValidAlert가 true를 반환하도록 Stubbing
        doReturn(true).when(alertService).isValidAlert(duplicateMockAlert);
        // AlertNotificationService의 isDuplicateAlert가 true를 반환하도록 Stubbing
        when(alertNotificationService.isDuplicateAlert(duplicateMockAlert)).thenReturn(true);

        // WHEN (실행)
        alertService.createAlert(duplicateMockAlert);

        // THEN (검증)
        verify(alertService, times(1)).isValidAlert(duplicateMockAlert); // isValidAlert 호출 검증
        verify(alertNotificationService, times(1)).isDuplicateAlert(duplicateMockAlert); // isDuplicateAlert 호출 검증

        // 이후 로직은 호출되지 않아야 함
        verify(alertRepository, never()).save(any());
        verify(alertNotificationService, never()).updateAlertStatistics(any());
        verify(alertNotificationService, never()).processImmediateNotification(any());
        verify(alertNotificationService, never()).updateDuplicatePreventionCache(any());

        verifyNoMoreInteractions(alertRepository, alertNotificationService);
    }
}
