package org.example.packetanomalydetection.entity.enums;

import lombok.Getter;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Getter
public enum AlertSeverity {
    LOW("낮음", 1),
    MEDIUM("보통", 2),
    HIGH("높음", 3 ),
    CRITICAL("심각", 4 );

    private final String level;
    private final int priority;


    private static final Map<Integer, AlertSeverity> PRIORITY_MAP =
            Arrays.stream(values())
                    .collect(Collectors.toMap(AlertSeverity::getPriority, Function.identity()));


    public static AlertSeverity fromPriority(int priority) {
        if (priority > 4 || priority == 0) {
            throw new IllegalArgumentException("유효하지 않은 우선순위 (유효 범위: 1-4)");
        }
        return PRIORITY_MAP.get(priority);
    }


    AlertSeverity(String level, int priority) {
        this.level = level;
        this.priority = priority;
    }

}
