# 구장별 날씨 위치

공개 시설 위치 메타데이터를 참고한 구장 주변 예보입니다. 현장 관측 장비의 실측값은 아니며 가까운 구장끼리는 예보가 같을 수 있습니다.

- 국제: https://sportsclub.sports.or.kr/club/gimhaetennisclub (주소 확인), https://ilsangkit.co.kr/sports/sports-7da16d5b7781030d (GeoCoordinates)
- 능동: https://smaxh.com/ko-KR/courts/8da28124-15da-4516-8e8e-d9f12e179f58 (GeoCoordinates). 지번 표기가 자료마다 달라 검색 지역은 삼문동으로 사용합니다.
- 동부: https://smaxh.com/ko-KR/courts/0d4261b1-3891-4305-ba85-53d75dd2c955 (주소·GeoCoordinates)
- 원도심: https://ilsangkit.co.kr/sports/sports-70e8caa6360499a4 (주소·GeoCoordinates)

네이버 버튼은 해당 구장의 소재 동 날씨 검색으로 연결합니다. 앱 안의 일별 예보는 기존 Open-Meteo 공급자를 유지하고 각 구장 좌표를 전달합니다. 예보 제공사의 격자와 업데이트 시각에 따라 네이버 표시와 차이가 있을 수 있습니다.

구장·좌표별 v3 캐시로 분리했습니다. 기존 단일 위치 v2 캐시는 재사용하지 않습니다. 구장 전환 시 이전 예보를 즉시 지우며 늦게 도착한 이전 구장 응답은 해당 구장 캐시에만 저장합니다. 설정의 개발자 잠금과 구장 공개 상태는 변경하지 않습니다.
