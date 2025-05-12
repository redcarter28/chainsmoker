# Use a slim official Python image
FROM python:3.13-bullseye

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /usr/src/app

# Copy and install Python dependencies
COPY req.txt ./

RUN pip uninstall jwt
RUN pip install --no-cache-dir -r req.txt


# Set up certs

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY keycloak.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Copy the application code
COPY ./ ./
# (and any other modules, assets/, db/ folders, etc.)

# Expose the Dash default port
EXPOSE 8080


# Run the app
CMD ["python", "app/chainsmoker_v2.1.py"]