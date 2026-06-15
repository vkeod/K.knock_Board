# Knock Boards

PHP + MySQL + Apache 게시판.

## 실행

```bash
cp .env.example .env
# .env 의 DB_PASS, MYSQL_ROOT_PASSWORD, APP_SECRET 을 32자 이상 랜덤 값으로 채우기
docker compose up -d --build
```

웹: http://localhost:8082
