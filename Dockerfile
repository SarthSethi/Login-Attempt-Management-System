# ---------- Stage 1: build the jar ----------
FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace

# Download dependencies first (cached as a separate layer)
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN chmod +x mvnw && ./mvnw -B -q dependency:go-offline

# Build the application (tests are run separately with ./mvnw test)
COPY src/ src/
RUN ./mvnw -B -q package -DskipTests

# ---------- Stage 2: small runtime image ----------
FROM eclipse-temurin:21-jre
WORKDIR /app

# Run as a non-root user
RUN useradd --system --uid 1001 --no-create-home lams
COPY --from=build /workspace/target/login-monitoring-system.jar app.jar
USER lams

# Tuned for small free-tier containers (about 512 MB RAM, low CPU)
ENV JAVA_OPTS="-XX:MaxRAMPercentage=70 -XX:+UseSerialGC -XX:TieredStopAtLevel=1 -Duser.timezone=UTC"

# The app listens on $PORT (Render sets it) or 8080 by default
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
