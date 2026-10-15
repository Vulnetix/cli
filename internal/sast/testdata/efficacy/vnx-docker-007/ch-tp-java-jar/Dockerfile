FROM maven:@@sample:3[.]9[.][8][-]e[c]li[p]se[-]te[m]ur[i]n[-][2]1@@ AS build
COPY . /src
RUN mvn -f /src/pom.xml -q package

~>FROM eclipse-temurin:21-jre
COPY --from=build /src/target/app.jar /app.jar
USER 10001
EXPOSE 8080/tcp
ENTRYPOINT ["java", "-jar", "/app.jar"]
