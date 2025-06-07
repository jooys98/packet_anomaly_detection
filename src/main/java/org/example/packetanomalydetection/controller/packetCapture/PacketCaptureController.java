package org.example.packetanomalydetection.controller.packetCapture;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.packetanomalydetection.service.packetData.PacketCaptureService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/packet-capture")
@RequiredArgsConstructor
public class PacketCaptureController {
    private final PacketCaptureService packetCaptureService;

    /**
     * 패킷 캡처 시작
     */
    @PostMapping("/start")
    public ResponseEntity<Map<String, Object>> startCapture() {
        log.info(" 패킷 캡처 시작 요청 받음");

//TODO : 트러블 슈팅 initializeCapture() 메서드가 동기적 수행, 블로킹 방식으로 동작해서 응답이 클라이언트에 전송되지 않음

        Map<String, Object> response = new HashMap<>();

        try {
            boolean started = packetCaptureService.initializeCapture();

            if (started) {
                response.put("status", "SUCCESS");
                response.put("message", "패킷 캡처가 시작되었습니다");
                response.put("captureStatus", "RUNNING");
                response.put("timestamp", LocalDateTime.now());
                return ResponseEntity.ok(response);
            } else {
                response.put("status", "ERROR");
                response.put("message", "패킷 캡처가 이미 실행 중이거나 시작할 수 없습니다");
                response.put("captureStatus", "FAILED");
                return ResponseEntity.badRequest().body(response);
            }
        } catch (Exception e) {
            log.error("❌ 패킷 캡처 시작 실패: {}", e.getMessage(), e);
            response.put("status", "ERROR");
            response.put("message", "패킷 캡처 시작 중 오류 발생: " + e.getMessage());
            response.put("captureStatus", "ERROR");
            return ResponseEntity.internalServerError().body(response);
        }
    }

    /**
     * 패킷 캡처 중지
     */
    @PostMapping("/stop")
    public ResponseEntity<Map<String, Object>> stopCapture() {
        log.info(" 패킷 캡처 중지 요청 받음");

        Map<String, Object> response = new HashMap<>();

        try {
            boolean stopped = packetCaptureService.cleanup();

            if (stopped) {
                response.put("status", "SUCCESS");
                response.put("message", "패킷 캡처가 중지되었습니다");
                response.put("captureStatus", "STOPPED");
                response.put("timestamp", LocalDateTime.now());
                return ResponseEntity.ok(response);
            } else {
                response.put("status", "ERROR");
                response.put("message", "패킷 캡처가 실행 중이지 않거나 중지할 수 없습니다");
                response.put("captureStatus", "NOT_RUNNING");
                return ResponseEntity.badRequest().body(response);
            }
        } catch (Exception e) {
            log.error("❌ 패킷 캡처 중지 실패: {}", e.getMessage(), e);
            response.put("status", "ERROR");
            response.put("message", "패킷 캡처 중지 중 오류 발생: " + e.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    /**
     * 패킷 캡처 상태 조회
     */
//    @GetMapping("/status")
//    public ResponseEntity<PacketCaptureStatusResponseDTO> getCaptureStatus() {
//        log.debug("📊 패킷 캡처 상태 조회 요청");
//
//        try {
//            PacketCaptureStatusResponseDTO status = packetCaptureService.getCaptureStatus();
//            return ResponseEntity.ok(status);
//        } catch (Exception e) {
//            log.error("❌ 패킷 캡처 상태 조회 실패: {}", e.getMessage(), e);
//            PacketCaptureStatusResponseDTO errorStatus = PacketCaptureStatusResponseDTO.builder()
//                    .isRunning(false)
//                    .captureMode("UNKNOWN")
//                    .errorMessage("상태 조회 중 오류 발생: " + e.getMessage())
//                    .timestamp(LocalDateTime.now())
//                    .build();
//            return ResponseEntity.internalServerError().body(errorStatus);
//        }
//    }

    /**
     * 패킷 캡처 재시작 (중지 후 시작)
     */
//    @PostMapping("/restart")
//    public ResponseEntity<Map<String, Object>> restartCapture() {
//        log.info("🔄 패킷 캡처 재시작 요청 받음");
//
//        Map<String, Object> response = new HashMap<>();
//
//        try {
//            boolean restarted = packetCaptureService.restartCapture();
//
//            if (restarted) {
//                response.put("status", "SUCCESS");
//                response.put("message", "패킷 캡처가 재시작되었습니다");
//                response.put("captureStatus", "RESTARTED");
//                response.put("timestamp", LocalDateTime.now());
//                return ResponseEntity.ok(response);
//            } else {
//                response.put("status", "ERROR");
//                response.put("message", "패킷 캡처 재시작에 실패했습니다");
//                return ResponseEntity.internalServerError().body(response);
//            }
//        } catch (Exception e) {
//            log.error("❌ 패킷 캡처 재시작 실패: {}", e.getMessage(), e);
//            response.put("status", "ERROR");
//            response.put("message", "패킷 캡처 재시작 중 오류 발생: " + e.getMessage());
//            return ResponseEntity.internalServerError().body(response);
//        }
//    }

}
