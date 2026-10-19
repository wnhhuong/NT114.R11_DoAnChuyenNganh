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
# Chạy bằng user thường thay vì root (sửa finding Semgrep missing-user-entrypoint)
RUN apk upgrade --no-cache && addgroup -S app && adduser -S -G app app

WORKDIR /app

COPY --from=builder --chown=app:app /build/build/libs/*.jar app.jar

USER app

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
