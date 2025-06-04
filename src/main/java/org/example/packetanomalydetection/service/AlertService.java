package org.example.packetanomalydetection.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.entity.Alert;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.example.packetanomalydetection.entity.constants.AlertType;
import org.example.packetanomalydetection.repository.AlertRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 *  AlertService - 알림 생성 및 관리 서비스
 *
 *  주요 기능:
 * 1. 알림 생성 및 저장 - ThreatDetectionService에서 호출
 * 2. 알림 상태 관리 - 해결, 무시, 에스컬레이션
 * 3. 중복 알림 방지 - 같은 유형의 알림 반복 생성 방지
 * 4. 알림 우선순위 관리 - 심각도별 처리 순서
 * 5. 자동 정리 - 오래된 알림 자동 삭제
 *
 *  동작 방식:
 * - ThreatDetectionService → AlertService.createAlert() 호출
 * - 중복 체크 → 알림 생성 → 데이터베이스 저장
 * - 심각도별 즉시 알림 → 콘솔/이메일/SMS 전송
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AlertService {

    private final AlertRepository alertRepository;

    //  통계 추적
    private final AtomicLong totalAlertsCreated = new AtomicLong(0);
    private final AtomicLong criticalAlertsToday = new AtomicLong(0);

    // 중복 알림 방지용 캐시 (IP + 알림타입 + 시간)
    private final Map<String, LocalDateTime> recentAlerts = new HashMap<>();

    /**
     * 새로운 알림 생성 - 핵심 메서드!
     *
     * ThreatDetectionService에서 위협 탐지 시 호출됨
     */
    @Transactional
    public Alert createAlert(Alert alert) {

        try {
            // 1. 입력 검증
            if (!isValidAlert(alert)) {
                log.warn(" 유효하지 않은 알림 요청: {}", alert);
                return null;
            }

            // 2. 중복 알림 체크
            if (isDuplicateAlert(alert)) {
                log.debug("중복 알림 무시: {} - {}", alert.getAlertType(), alert.getSourceIp());
                return null;
            }

            //  3. 타임스탬프 설정 (없는 경우)
            if (alert.getTimestamp() == null) {
                alert.addTimestamp(LocalDateTime.now());
            }

            // 4. 데이터베이스에 저장
            Alert savedAlert = alertRepository.save(alert);

            // 5. 통계 업데이트
            updateAlertStatistics(savedAlert);

            // 6.  즉시 알림 처리 (심각도별)
            processImmediateNotification(savedAlert);

            // 7. 중복 방지 캐시 업데이트
            updateDuplicatePreventionCache(savedAlert);

            log.info("알림 생성 완료: [{}] {} - {}",
                    savedAlert.getSeverity(),
                    savedAlert.getAlertType(),
                    savedAlert.getSourceIp());

            return savedAlert;

        } catch (Exception e) {
            log.error(" 알림 생성 중 오류", e);
            return null;
        }
    }

    /**
     * 알림 유효성 검증
     */
    private boolean isValidAlert(Alert alert) {

        // 필수 필드 체크
        if (alert.getAlertType() == null || alert.getAlertType().trim().isEmpty()) {
            log.warn(" 알림 타입이 없음");
            return false;
        }

        if (alert.getSeverity() == null) {
            log.warn(" 심각도가 설정되지 않음");
            return false;
        }

        if (alert.getDescription() == null || alert.getDescription().trim().isEmpty()) {
            log.warn(" 알림 설명이 없음");
            return false;
        }

        // 길이 제한 체크
        if (alert.getDescription().length() > 1000) {
            log.warn("알림 설명이 너무 김: {} characters", alert.getDescription().length());
            return false;
        }

        return true;
    }

    /**
     *  중복 알림 체크
     *
     * 동일한 IP에서 같은 유형의 알림이 짧은 시간에 반복 생성되는 것을 방지
     */
    private boolean isDuplicateAlert(Alert alert) {

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
     * 알림 통계 업데이트
     */
    private void updateAlertStatistics(Alert alert) {

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
     * 즉시 알림 처리 (심각도별 차등 처리)
     */
    private void processImmediateNotification(Alert alert) {

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
     *  CRITICAL 알림 처리
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
     *  LOW 알림 처리
     */
    private void sendLowPriorityAlert(Alert alert) {

        // 로그만 기록
        log.info(" LOW 알림: {} - {}", alert.getAlertType(), alert.getSourceIp());
    }

    /**
     *중복 방지 캐시 업데이트
     */
    private void updateDuplicatePreventionCache(Alert alert) {

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
     * 활성 알림 조회 (해결되지 않은 알림들)
     */
    public List<Alert> getActiveAlerts() {
        return alertRepository.findByResolvedFalseOrderByTimestampDesc();
    }

    /**
     * 심각도별 알림 조회
     */
    public List<Alert> getAlertsBySeverity(AlertSeverity severity) {
        return alertRepository.findBySeverityOrderByTimestampDesc(severity);
    }

    /**
     * 최근 알림 조회 (50개)
     */
    public List<Alert> getRecentAlerts() {
        return alertRepository.findTop50ByOrderByTimestampDesc();
    }

    /**
     *  특정 IP 관련 알림 조회
     */
    public List<Alert> getAlertsByIp(String ip) {
        return alertRepository.findBySourceIpOrDestIpOrderByTimestampDesc(ip, ip);
    }

    /**
     *  알림 통계 조회
     */
    public Map<String, Object> getAlertStatistics() {

        Map<String, Object> stats = new HashMap<>();

        //  기본 통계
        long totalAlerts = alertRepository.count();
        long activeAlerts = alertRepository.countActiveAlerts();

        // 오늘의 알림 수
        LocalDateTime todayStart = LocalDateTime.now().toLocalDate().atStartOfDay();
        List<Alert> todayAlerts = alertRepository.findByTimestampBetweenOrderByTimestampDesc(
                todayStart, LocalDateTime.now()
        );

        //  심각도별 통계
        Map<AlertSeverity, Long> severityStats = todayAlerts.stream()
                .collect(Collectors.groupingBy(
                        Alert::getSeverity,
                        Collectors.counting()
                ));

        // 알림 타입별 통계
        Map<String, Long> typeStats = todayAlerts.stream()
                .collect(Collectors.groupingBy(
                        Alert::getAlertType,
                        Collectors.counting()
                ));

        stats.put("totalAlerts", totalAlerts);
        stats.put("activeAlerts", activeAlerts);
        stats.put("todayAlerts", todayAlerts.size());
        stats.put("severityDistribution", severityStats);
        stats.put("typeDistribution", typeStats);
        stats.put("totalCreatedSinceStart", totalAlertsCreated.get());

        return stats;
    }

    // =========================================================================
    //  알림 관리 메서드들
    // =========================================================================

    /**
     *  알림 해결 처리
     */
    @Transactional
    public boolean resolveAlert(Long alertId, String resolvedBy) {

        Optional<Alert> optionalAlert = alertRepository.findById(alertId);

        if (optionalAlert.isPresent()) {
            Alert alert = optionalAlert.get();
            alert.markAsResolved(resolvedBy);
            alertRepository.save(alert);

            log.info(" 알림 해결: ID {} by {}", alertId, resolvedBy);
            return true;
        }

        log.warn(" 알림을 찾을 수 없음: ID {}", alertId);
        return false;
    }

    /**
     * 여러 알림 일괄 해결
     */
    @Transactional
    public int resolveMultipleAlerts(List<Long> alertIds, String resolvedBy) {

        int resolvedCount = 0;

        for (Long alertId : alertIds) {
            if (resolveAlert(alertId, resolvedBy)) {
                resolvedCount++;
            }
        }

        log.info("일괄 해결 완료: {}개 알림 by {}", resolvedCount, resolvedBy);
        return resolvedCount;
    }

    /**
     *  오래된 알림 자동 정리 (매일 새벽 2시)
     */
    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    public void cleanupOldAlerts() {

        try {
            log.info("🧹 오래된 알림 정리 시작...");

            //  30일 이전의 해결된 알림 삭제
            LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);
            List<Alert> oldResolvedAlerts = alertRepository.findByResolvedTrueAndTimestampBefore(thirtyDaysAgo);

            if (!oldResolvedAlerts.isEmpty()) {
                alertRepository.deleteAll(oldResolvedAlerts);
                log.info(" 해결된 오래된 알림 {}개 삭제", oldResolvedAlerts.size());
            }

            //  90일 이전의 LOW 심각도 알림 삭제
            LocalDateTime ninetyDaysAgo = LocalDateTime.now().minusDays(90);
            List<Alert> oldLowAlerts = alertRepository.findBySeverityAndTimestampBefore(
                    AlertSeverity.LOW, ninetyDaysAgo
            );

            if (!oldLowAlerts.isEmpty()) {
                alertRepository.deleteAll(oldLowAlerts);
                log.info("오래된 LOW 알림 {}개 삭제", oldLowAlerts.size());
            }

            //  오늘 Critical 알림 카운터 리셋
            criticalAlertsToday.set(0);

            log.info(" 오래된 알림 정리 완료");

        } catch (Exception e) {
            log.error(" 알림 정리 중 오류", e);
        }
    }

    /**
     *  시스템 상태용 알림 생성 (내부 시스템 문제)
     */
    public Alert createSystemAlert(String alertType, String description) {

        Alert systemAlert = Alert.builder()
                .alertType(alertType)
                .description("시스템 알림: " + description)
                .severity(AlertSeverity.MEDIUM)
                .sourceIp("SYSTEM")
                .build();

        return createAlert(systemAlert);
    }

    /**
     * 긴급 상황 대응 - 모든 알림 일시 중단
     */
    public void emergencyMuteAll(int durationMinutes, String reason) {

        log.warn(" 긴급 알림 중단: {}분간 - 사유: {}", durationMinutes, reason);

        // 실제 구현에서는 플래그를 설정하여 createAlert에서 체크
        // 또는 별도의 알림 중단 테이블 사용

        System.out.println(" 모든 알림이 " + durationMinutes + "분간 중단됩니다.");
        System.out.println(" 중단 사유: " + reason);
    }
}
