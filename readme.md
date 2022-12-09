# Nginx mqtt https termination test

This is a PoC that X.509 certificates can be used to supply authentication information to a non-SSL enabled mosquitto mqtt server which is fronted by a SSL terminating nginix load-balancer.
The approach used is for the client to supply a username in addition to it's SSL certificate. The nginx uses a njs file (mqtt.js, configured in stream_mqtt_authentication.conf) to check that the username supplied corresponds to the CN of the certificate and ends the connection if there is no match. In this way the mosquitto server can rely on the username being correct and can configure acls based on the username.

To run, checkout the repository, change into the directory and type ```docker-compose up --abort-on-container-exit```. Tests defined in test_certificates.py will automatically be run. The testing is implemented using pytest and leaverages a background container which continously posts messages. The tests consist in checking if messages can be received with the supplied credentials.

The tests that are implememented for mosquitto are:
 1. GB certificate has been signed by CA and has the right subject name => can read from topic
 2. GB certificate has been signed by CA, but does not have the right subject name => cannot read from topic
 3. GB certificate has been signed by non trusted CA but has the right subject name => cannot read from topic
 4. GB certificate does not correspond to username => cannot read from topic


## keys and certificates
Keys and certificates have already been generated and are contained in the ssl folder.