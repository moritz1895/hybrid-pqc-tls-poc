FROM maven:3.9-eclipse-temurin-25 AS builder
WORKDIR /app
COPY pom.xml ./
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -DskipTests -q

FROM eclipse-temurin:25-jre-alpine AS runtime
WORKDIR /app

RUN addgroup -g 10001 -S poc && adduser -u 10001 -S poc -G poc
USER poc

COPY --from=builder /app/target/*.jar app.jar

# CLI demo adapter: runs once (hybrid PQC TLS 1.3 handshake over loopback
# sockets, software backend BCJSSE) and then exits - no long-running server,
# hence no EXPOSE/HEALTHCHECK. Only the software path is containerizable -
# the IBM-CCA path needs real z/OS/ICSF/CEX8P hardware, see README.md.
ENTRYPOINT ["java", "-jar", "app.jar"]
