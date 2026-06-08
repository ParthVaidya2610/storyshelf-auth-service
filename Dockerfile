FROM eclipse-temurin:21-jdk

WORKDIR /app

COPY target/*.jar app.jar

RUN useradd -m springuser

USER springuser

EXPOSE 8082

ENTRYPOINT ["java","-jar","app.jar"]