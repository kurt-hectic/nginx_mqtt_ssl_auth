import pytest
import requests
import ssl
import time

import paho.mqtt.client as mqtt

data_received = False

def setup_mqtt_client(certfile,keyfile,username,pw="wis"):

    client = mqtt.Client()
    client.tls_set(certfile=certfile,
               keyfile=keyfile,
               ca_certs="./wisca.crt",
               cert_reqs=ssl.CERT_REQUIRED,
               tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.on_message = on_message
    client.username_pw_set(username, pw)
    client.connect("node-ch.wis2.wmo.int", 8883)
    client.subscribe("test", qos=1)
    
    client.loop_start()

    time.sleep(2)
    
    client.loop_stop()


def on_message(client, userdata, message):
    global data_received
    
    print("%s %s" % (message.topic, message.payload))
    data_received = message.payload


def test_sub_certificate_and_subject():
    global data_received
    data_received = False

    setup_mqtt_client("./gb_fr.crt","./gb_fr.key","gb-fr.wis2.wmo.int")
    
    assert data_received

def test_sub_certificate_and_subject_non_authorized():
    global data_received
    data_received = False

    setup_mqtt_client("./gb_ma.crt","./gb_ma.key","gb-ma.wis2.wmo.int")
    
    assert not data_received

def test_sub_certificate_and_username_no_match():
    global data_received
    data_received = False

    setup_mqtt_client("./gb_ma.crt","./gb_ma.key","gb-fr.wis2.wmo.int")
    
    assert not data_received

    
@pytest.mark.filterwarnings("ignore")
def test_sub_fake_certificate():
    global data_received
    data_received = False

    setup_mqtt_client("./gb_fr_fake.crt","./gb_fr.key","gb-fr.wis2.wmo.int")
    
    assert not data_received