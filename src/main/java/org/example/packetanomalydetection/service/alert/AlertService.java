package org.example.packetanomalydetection.service.alert;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.entity.Alert;
import org.example.packetanomalydetection.entity.enums.AlertSeverity;
import org.example.packetanomalydetection.repository.AlertRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;


/**
 * AlertService - 알림 생성 및 검증 , 스케줄링  서비스
 * 주요 기능:
 * 알림 생성 및 저장 - ThreatDetectionService 에서 호출
 * 알림 상태 관리 - 해결, 무시, 에스컬레이션
 * 자동 정리 - 오래된 알림 자동 삭제

 * 동작 방식:
 * - ThreatDetectionService → AlertService.createAlert() 호출
 * - 중복 체크 → 알림 생성 → 데이터베이스 저장
 * - 심각도별 즉시 알림 → 콘솔/이메일/SMS 전송
 */

@Service
@RequiredArgsConstructor
@Slf4j
public class AlertService {

    private final AlertRepository alertRepository;
    private final AlertNotificationService alertNotificationService;


    /**
     * 새로운 알림 생성
     * ThreatDetectionService 에서 위협 탐지 시 호출됨
     */
    @Transactional
    public void createAlert(Alert alert) {

        try {
            // 1. 입력 검증
            if (!isValidAlert(alert)) {
                log.warn(" 유효하지 않은 알림 요청: {}", alert);

                return;
            }

            // 2. 중복 알림 체크
            if (alertNotificationService.isDuplicateAlert(alert)) {
                log.debug("중복 알림 무시: {} - {}", alert.getAlertType(), alert.getSourceIp());
                return;
            }

            //  3. 타임스탬프 설정 (없는 경우)
            if (alert.getTimestamp() == null) {
                alert.addTimestamp(LocalDateTime.now());
            }

            // 4. 데이터베이스에 저장
            Alert savedAlert = alertRepository.save(alert);

            // 5. 통계 업데이트
            alertNotificationService.updateAlertStatistics(savedAlert);

            // 6.  즉시 알림 처리 (심각도별)
            alertNotificationService.processImmediateNotification(savedAlert);

            // 7. 중복 방지 캐시 업데이트
            alertNotificationService.updateDuplicatePreventionCache(savedAlert);

            log.info("알림 생성 완료: [{}] {} - {}",
                    savedAlert.getSeverity(),
                    savedAlert.getAlertType(),
                    savedAlert.getSourceIp());

        } catch (Exception e) {
            log.error(" 알림 생성 중 오류", e);
        }
    }



    /**
     * 오래된 알림 자동 정리 (매일 새벽 2시)
     */
    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    public void cleanupOldAlerts() {

        try {
            log.info(" 오래된 알림 정리 시작...");

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
            alertNotificationService.setCriticalAlertsToday();

            log.info(" 오래된 알림 정리 완료");

        } catch (Exception e) {
            log.error(" 알림 정리 중 오류", e);
        }
    }


    /**
     * 알림 유효성 검증
     * 검증- true
     */
    public boolean isValidAlert(Alert alert) {

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

}
