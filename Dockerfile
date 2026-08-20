FROM maven:3.9.16-eclipse-temurin-25 AS build

WORKDIR /workspace

COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
COPY src/ src/

RUN chmod +x mvnw && ./mvnw -B -DskipTests package

FROM eclipse-temurin:25-jre

WORKDIR /app

COPY --from=build /workspace/target/*.jar app.jar

RUN useradd -m springuser

USER springuser

EXPOSE 8092

ENTRYPOINT ["java","-jar","app.jar"]
