# Build stage
FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app
# Copy pom.xml and src using paths relative to the repository root
COPY java-packet-analyzer/pom.xml ./pom.xml
COPY java-packet-analyzer/src ./src
RUN mvn clean package -DskipTests

# Run stage
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/java-packet-analyzer-1.0-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
