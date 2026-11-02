# Stage 1: Build
FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /build

COPY app/ .

# Rỗng khi build bình thường; kịch bản "có lỗ hổng" truyền -PtomcatVersion/-PjacksonVersion
ARG GRADLE_ARGS=""
RUN ./gradlew bootJar --no-daemon ${GRADLE_ARGS}

# Stage 2: Runtime
FROM eclipse-temurin:21-jre-alpine

# Cập nhật gói hệ điều hành đã có bản vá (vd. CVE-2026-77214 libexpat 2.8.5-r0 -> 2.9.0-r0)
# Chạy bằng user thường thay vì root (sửa finding Semgrep missing-user-entrypoint); UID cố định 10001
RUN apk upgrade --no-cache && addgroup -S -g 10001 app && adduser -S -u 10001 -G app app

WORKDIR /app

COPY --from=builder --chown=app:app /build/build/libs/*.jar app.jar

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
