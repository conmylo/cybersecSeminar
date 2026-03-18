import paho.mqtt.client as mqtt
import json
import time
import random
import uuid
from datetime import datetime, UTC

BROKER = "localhost"
PORT = 8883
TOPIC = "iot/temperature"
CLIENT_ID = f"iot-publisher-{uuid.uuid4().hex[:8]}"
CA_CERT = r"C:\Users\conmy\Documents\project9\q3_tls\certs\ca.crt"

def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print(f"Publisher connected with CLIENT_ID: {CLIENT_ID}")
    else:
        print(f"Failed to connect, return code {reason_code}")

client = mqtt.Client(
    client_id=CLIENT_ID,
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2
)
client.on_connect = on_connect
client.username_pw_set("publisher_user", "pub_pass123")
client.tls_set(ca_certs=CA_CERT)
client.tls_insecure_set(True)
client.connect(BROKER, PORT, keepalive=60)
client.loop_start()

try:
    while True:
        payload = {
            "sensor_id": "temp_sensor",
            "temperature_c": round(random.uniform(20.0, 30.0), 2),
            "timestamp": datetime.now(UTC).isoformat()
        }
        client.publish(TOPIC, json.dumps(payload))
        print(f"Published: {payload}")
        time.sleep(5)
except KeyboardInterrupt:
    print("Stop publisher!")
    client.loop_stop()
    client.disconnect()