FROM eclipse-temurin:21-jdk

WORKDIR /app

COPY build/libs/*.jar app.jar

ENV DB_URL=jdbc:postgresql://postgres:5432/queue_db
ENV DB_USERNAME=postgres
ENV DB_PASSWORD=postgres
ENV SERVER_PORT=8083

EXPOSE 8083

ENTRYPOINT ["java", "-jar", "app.jar"]