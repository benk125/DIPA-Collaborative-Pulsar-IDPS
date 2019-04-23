
import pulsar

client = pulsar.Client('pulsar://192.168.1.1:6650')

producer = client.create_producer(
                'non-persistent://sample/standalone/ns1/my-topic')

for i in range(10):
    # Publish a message and wait until it is persisted
    producer.send(('Hello-%d' % i).encode('utf-8'))

client.close()
