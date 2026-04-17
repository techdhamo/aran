FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
COPY aran-api-gateway/pom.xml ./aran-api-gateway/
COPY aran-api-gateway/src ./aran-api-gateway/src
COPY aran-iam-service/pom.xml ./aran-iam-service/
COPY aran-iam-service/src ./aran-iam-service/src
COPY aran-tenant-service/pom.xml ./aran-tenant-service/
COPY aran-tenant-service/src ./aran-tenant-service/src
COPY aran-telemetry-service/pom.xml ./aran-telemetry-service/
COPY aran-telemetry-service/src ./aran-telemetry-service/src
RUN mvn clean package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /build/aran-tenant-service/target/aran-tenant-service-1.0.0.jar app.jar
EXPOSE 8082
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
