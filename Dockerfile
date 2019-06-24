############################################################################
#                                                                          #
# @Author: Cuong Do                                                        #
# References:                                                              #
# https://github.com/vdenotaris/spring-boot-security-saml-sample           #
#                                                                          #
############################################################################

# Use gradle to pack a standalone executable fat-JAR file.
FROM openjdk:8 AS TEMP_BUILD_IMAGE

# Set up working directory to copy gradle
ENV APP_HOME=/usr/app/
WORKDIR $APP_HOME

# Copy gradle into working directory
COPY build.gradle settings.gradle gradlew $APP_HOME
COPY gradle $APP_HOME/gradle

# At this point, there is no other source code files exists in the directory. So build will fail. But before that it will download the dependencies.
RUN ./gradlew build || return 0 

# Copy source code into working directory
COPY . .

# Setup working directory to run update-certificate.sh
WORKDIR $APP_HOME/src/main/resources/saml/

# Retrieve a fresh SSO Circle's certificate and store it within the application keystore
RUN chmod +x update-certificate.sh
RUN sh ./update-certificate.sh

# Setup working directory to build gradle
WORKDIR $APP_HOME

# Build Gradle
RUN ./gradlew build

# Base Alpine Linux based image with OpenJDK JRE only
FROM openjdk:8-jdk-alpine

# Project maintainer
MAINTAINER do.cuong@mulodo.com

# Get the packed fat-JAR
COPY --from=TEMP_BUILD_IMAGE /usr/app/build/libs/*.jar app.jar

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Setup application startup jar
CMD ["java","-jar","app.jar"]  

############################################################################