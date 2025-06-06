package org.example.packetanomalydetection.service.alert;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.entity.Alert;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
@Slf4j
@RequiredArgsConstructor
/*
 * 중복 알림 방지 - 같은 유형의 알림 반복 생성 방지
 * 알림 우선순위 관리 - 심각도별 처리 순서
 */

public class AlertNotificationService {

    //  통계 추적
    @Getter
    private final AtomicLong totalAlertsCreated = new AtomicLong(0);
    private final AtomicLong criticalAlertsToday = new AtomicLong(0);

    // 중복 알림 방지용 캐시 (IP + 알림타입 + 시간)
    private final Map<String, LocalDateTime> recentAlerts = new ConcurrentHashMap<>();


    /**
     * 즉시 알림 처리 (심각도별 차등 처리)
     */
    public void processImmediateNotification(Alert alert) {

        AlertSeverity severity = alert.getSeverity();

        switch (severity) {
            case CRITICAL:
                //  최고 심각도: 즉시 모든 채널로 알림
                sendCriticalAlert(alert);
                break;

            case HIGH:
                // 높음: 콘솔 + 로그 + 이메일
                sendHighPriorityAlert(alert);
                break;

            case MEDIUM:
                //  보통: 콘솔 + 로그
                sendMediumPriorityAlert(alert);
                break;

            case LOW:
                //  낮음: 로그만
                sendLowPriorityAlert(alert);
                break;
        }
    }

    /**
     * 알림 통계 업데이트
     */
    public void updateAlertStatistics(Alert alert) {

        //  전체 알림 수 증가
        totalAlertsCreated.incrementAndGet();

        //  오늘 CRITICAL 알림 수 추적
        if (AlertSeverity.CRITICAL.equals(alert.getSeverity())) {
            criticalAlertsToday.incrementAndGet();
        }

        log.debug(" 알림 통계: 총 {}개, 오늘 Critical {}개",
                totalAlertsCreated.get(), criticalAlertsToday.get());
    }


    /**
     * 중복 방지 캐시 업데이트
     */
    public void updateDuplicatePreventionCache(Alert alert) {

        String duplicateKey = String.format("%s:%s",
                alert.getSourceIp() != null ? alert.getSourceIp() : "unknown",
                alert.getAlertType()
        );

        recentAlerts.put(duplicateKey, alert.getTimestamp());

        //  오래된 캐시 엔트리 정리 (1시간 이상)
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        recentAlerts.entrySet().removeIf(entry ->
                entry.getValue().isBefore(oneHourAgo)
        );
    }


    /**
     * 중복 알림 체크
     * 동일한 IP 에서 같은 유형의 알림이 짧은 시간에 반복 생성되는 것을 방지
     */
    public boolean isDuplicateAlert(Alert alert) {

        // 중복 체크 키 생성 (IP + 알림타입)
        String duplicateKey = String.format("%s:%s",
                alert.getSourceIp() != null ? alert.getSourceIp() : "unknown",
                alert.getAlertType()
        );

        //  최근 알림 시간 확인
        LocalDateTime lastAlertTime = recentAlerts.get(duplicateKey);

        if (lastAlertTime != null) {
            // 5분 이내에 같은 알림이 있었는지 확인
            LocalDateTime fiveMinutesAgo = LocalDateTime.now().minusMinutes(5);

            if (lastAlertTime.isAfter(fiveMinutesAgo)) {
                log.debug(" 중복 알림 탐지: {} (마지막: {})", duplicateKey, lastAlertTime);
                return true;
            }
        }

        return false;
    }

    /**
     * 알림 리셋
     */

    public void setCriticalAlertsToday() {
        this.criticalAlertsToday.set(0);
    }

    /**
     * CRITICAL 알림 처리
     */
    private void sendCriticalAlert(Alert alert) {

        //  콘솔에 강조 표시
        System.out.println("\n" + "=".repeat(60));
        System.out.println(" =============CRITICAL SECURITY ALERT============= ");
        System.out.println("시간: " + alert.getTimestamp());
        System.out.println("유형: " + alert.getAlertType());
        System.out.println("출발지: " + alert.getSourceIp());
        System.out.println("설명: " + alert.getDescription());
        System.out.println("=".repeat(60) + "\n");


        log.error(" CRITICAL 알림: {} - {}", alert.getAlertType(), alert.getSourceIp());
    }

    /**
     * HIGH 알림 처리
     */
    private void sendHighPriorityAlert(Alert alert) {

        System.out.println(" [HIGH] " + alert.getAlertType() + " - " + alert.getSourceIp());
        System.out.println("   → " + alert.getDescription().split("\n")[0]); // 첫 줄만


        log.warn("HIGH 알림: {} - {}", alert.getAlertType(), alert.getSourceIp());
    }

    /**
     * MEDIUM 알림 처리
     */
    private void sendMediumPriorityAlert(Alert alert) {

        System.out.println("[MED] " + alert.getAlertType() + " - " + alert.getSourceIp());

        log.info("MEDIUM 알림: {} - {}", alert.getAlertType(), alert.getSourceIp());
    }

    /**
     * LOW 알림 처리
     */
    private void sendLowPriorityAlert(Alert alert) {

        // 로그만 기록
        log.info(" LOW 알림: {} - {}", alert.getAlertType(), alert.getSourceIp());
    }
}
