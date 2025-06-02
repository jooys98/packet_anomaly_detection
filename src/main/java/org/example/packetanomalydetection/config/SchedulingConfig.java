package org.example.packetanomalydetection.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

/**
 * 다수의 스레드 병렬 작업 처리를 위한 클래스
 */
@Configuration
public class SchedulingConfig implements SchedulingConfigurer {

    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
        //최대 5개의 스케줄된 작업이 동시 실행 가능
        taskScheduler.setPoolSize(5);

        //로그에서 어떤 작업인지 식별할 수 있게 해줌(모니터링)
        taskScheduler.setThreadNamePrefix("security-monitor-");
        taskScheduler.initialize();
        taskRegistrar.setTaskScheduler(taskScheduler);
    }
}