FROM maven:@@sample:3[.]9[-][e]cl[i]ps[e][-]t[e]mu[r]in[-]21@@ AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -q package -DskipTests

~>FROM eclipse-temurin:21-jre AS runtime
COPY --from=build /build/target/api.jar /opt/api.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/opt/api.jar"]
