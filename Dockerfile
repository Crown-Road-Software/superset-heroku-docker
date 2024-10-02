FROM apache/superset
# Switching to root to install the required packages
USER root
# Install the Postgres driver to connect to the metadata database
RUN pip install psycopg2-binary Authlib
# Switching back to using the `superset` user
USER superset
# Add configuration
COPY custom_security_manager.py .
COPY superset_config.py .
