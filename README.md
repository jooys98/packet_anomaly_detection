

# 네트워크 패킷 캡처 및 보안 모니터링 시스템

[![Project Status](https://img.shields.io/badge/Status-[진행중]-blue)](https://github.com/jooys98/packet_anomaly_detection/commits/main)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/jooys98/packet_anomaly_detection)](https://github.com/jooys98/packet_anomaly_detection/commits)



[![Java](https://img.shields.io/badge/Java-007396?style=flat-square&logo=java&logoColor=white)](https://www.java.com/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-6DB33F?style=flat-square&logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=flat-square&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Gradle](https://img.shields.io/badge/Gradle-02303A?style=flat-square&logo=gradle&logoColor=white)](https://gradle.org/)
[![JUnit5](https://img.shields.io/badge/JUnit5-25A162?style=flat-square&logo=junit5&logoColor=white)](https://junit.org/junit5/)
[![Mockito](https://img.shields.io/badge/Mockito-25A162?style=flat-square&logo=mockito&logoColor=white)](https://site.mockito.org/)
[![Swagger](https://img.shields.io/badge/Swagger-85EA2D?style=flat-square&logo=swagger&logoColor=black)](https://swagger.io/)



🔍 이 프로젝트는 **대표적인 네트워크 공격인 포트 공격, DDos 공격 , 패킷 분석의 내용들을 기반으로 침입 탐지 시스템** 을 학습하기 위해 개발되었습니다. **패킷 캡처 기능과 간단한 규칙 기반 이상 패턴 탐지로 위험도 별 알림 생성 , 날짜별 알림 통계 조회 기능** 을 제공하여 **효율적인 네트워크 보안 모니터링에** 기여합니다.


* **개발 기간:** 2025.05.15 ~ ing
* **UML 다이어그램:** https://jooys98.atlassian.net/wiki/x/ZoAC
* **프로젝트 개선 과정 및 트러블 슈팅:** https://whispering-shoemaker-e1d.notion.site/20945e7562a58027ac2ade2344e7f08a?source=copy_link

## ✨ 주요 기능

-   **기능 1 실시간 패킷 캡처 기능**: Pcap4j 를 활용한 패킷 캡처 기능을 제공하며 RESTAPI로 이를 제어할 수 있습니다. 또한  패킷 필터 설정으로 원하는  프로토콜과 포트 번호, 대역폭을 선택할 수 있습니다.
-   **기능 2 간단한 규칙 기반 이상 패턴 탐지로 위험도 별 알림 생성 및 조회**: 연속적인 포트 스캐닝 탐지, 대용량 패킷 탐지 ,의심스러운 포트 접근 탐지가 가능하며 이를 기반으로 심각도를 측정하여 알림으로 생성됩니다.
-   **기능 3 날짜 별 알림 통계 조회 기능**: 해당 날짜에 생성된 공격 알림의 위험도와 네트워크 공격 분포를 통계로 보여줍니다.
-   **기능 4 의심스러운 네트워크 활동 정보 조회/통계 기능 **: 사용자가 정한 접근 수 임계값과 날짜를 활용하여 의심스러운 소스 IP + 프로토콜 조합을 조회할 수 있습니다
-   **기능 5 운영체제 별 실제 패킷 캡처와 시뮬레이션 모드 자동 선택 기능**: 운영체제 환경을 기반으로 시뮬레이션 모드와 실제패킷 캡처 모드를 자동으로 선택합니다(MAC - 시뮬레이션 모드/window - WinPcap 또는 Npcap/ linux - libpcap-dev 설치필요)  


## 🛠️ 기술 스택
-  **백엔드 언어**	         
   : Java 11
   
-  **백엔드 프레임워크**        
   : SpringBoot 3.5.0
   
-  **빌드 도구**	              
   : Gradle
   
-  **데이터베이스**	           
   : MySQL 8.0
   
-  **ORM**	                 
   : JPA
   
-  **API 문서화**	    
   : Swagger openAPI 3.0.0

 -  **테스트**	                
   : JUnit 5, Mockito, Spring Test

 -  **기타 라이브러리**	          
   : Pcap4j



## 🚀 Installation & Setup (설치 및 실행 방법)

로컬 환경에서 프로젝트를 실행하기 위한 지침입니다.

```bash
# 1. 레포지토리 클론
git clone https://github.com/jooys98/packet_anomaly_detection.git
git pull origin refactoring

# 2. 의존성 설치
./gradlew build

# 3. 애플리케이션 실행
./gradlew bootRun

# 4. 패킷 캡처 라이브러리
window -  WinPcap 또는 Npcap 설치 ( https://npcap.com/)
linux - sudo apt-get install libpcap-dev , sudo setcap cap_net_raw,cap_net_admin=eip java
mac - 시뮬레이션 모드 Pcap4j 호환 문제
```

## ‼️ 향후 개발 계획

-  다양한 공격 탐지 옵션 추가
-  시스템 안정성과 사용자 친화적인 ui를 위한 커스텀 예외처리 
-  단위 테스트 커버리지 80% 달성
-  성능 최적화 (메모리 사용량 개선)
  
