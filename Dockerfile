FROM openjdk:17-jdk-slim
ENV APP_HOME /app/
COPY movies-api-1.0.0.jar $APP_HOME
EXPOSE 8081
ENV JAVA_OPTS=""
WORKDIR $APP_HOME
ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar movies-api-1.0.0.jar" ]