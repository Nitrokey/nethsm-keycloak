ARG KEYCLOAK_VERSION=26.8.2
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}

# The provider jar plus kotlin-stdlib -- everything Gradle's collectRuntimeJars staged.
# Build context is the repo root, so run `./gradlew build` first.
# Keycloak has one unrestricted classloader and gives providers/ precedence over its
# own libraries, so nothing else belongs in here.
COPY build/providers/ /opt/keycloak/providers/

# Registers the providers in the server's provider registry. Required after any change
# to providers/, and the reason `start-dev` alone is not enough.
RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev"]
