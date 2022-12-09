import paho.mqtt.client as mqtt 
from random import randrange, uniform
import time
import ssl

time.sleep(5)

mqttBroker = "node-ch.wis2.wmo.int" 

client = mqtt.Client("keepPublisher")

client.tls_set(certfile="./node_ch.crt",
               keyfile="./node_ch.key",
               ca_certs="./wisca.crt",
               cert_reqs=ssl.CERT_REQUIRED)
               
client.username_pw_set("node-ch.wis2.wmo.int","wis")

client.connect(mqttBroker,8883) 

while True:
    randNumber = uniform(20.0, 21.0)
    client.publish("test", randNumber)
    #print("Just published " + str(randNumber) + " to topic test")
    time.sleep(1)