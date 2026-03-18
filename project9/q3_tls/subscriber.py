import paho.mqtt.client as mqtt
import random
import string

CA_CERT = r"C:\Users\conmy\Documents\project9\q3_tls\certs\ca.crt"

def generate_client_id(prefix):
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{prefix}-{random_suffix}"

broker = "localhost"
port = 8883
topic = "iot/temperature"
client_id = generate_client_id("subscriber")
print(f"Subscriber ON - Client ID: {client_id}")

def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print("Connected to MQTT broker successfully")
        client.subscribe(topic, qos=0)
    else:
        print(f"Connection failed with code {reason_code}")

def on_message(client, userdata, msg):
    print(f"Received on {msg.topic}: {msg.payload.decode()}")

client = mqtt.Client(
    client_id=client_id,
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2
)
client.on_connect = on_connect
client.on_message = on_message
client.username_pw_set("subscriber_user", "sub_pass123")
client.tls_set(ca_certs=CA_CERT)
client.tls_insecure_set(True)
client.connect(broker, port)
client.loop_forever()