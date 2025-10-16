# =============================================
# Multi-stage Dockerfile for Spring Boot (Java 21)
# =============================================

# ---- Build stage ----
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /app

# Leverage Docker layer caching: only re-download deps when pom changes
COPY pom.xml ./
COPY .mvn/ .mvn/
COPY mvnw mvnw
RUN chmod +x mvnw || true

# Pre-fetch dependencies
RUN ./mvnw -q -DskipTests dependency:go-offline

# Copy sources and build
COPY src ./src
RUN ./mvnw -q -DskipTests package

# ---- Runtime stage ----
FROM eclipse-temurin:21-jre
WORKDIR /app

# Copy the fat jar from builder (use wildcard because artifact name may vary)
COPY --from=builder /app/target/*.jar /app/app.jar

# App port
EXPOSE 1001

# JVM and Spring defaults (can be overridden at runtime)
ENV JAVA_OPTS="-Xms256m -Xmx512m" \
    SERVER_PORT=1001 \
    SPRING_PROFILES_ACTIVE=default

# Health-friendly start
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Dserver.port=$SERVER_PORT -jar /app/app.jar"]


