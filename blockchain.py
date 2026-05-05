import hashlib
import time

class Block:
    def __init__(self, data, prev_hash="0"):
        self.timestamp = time.time()
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        content = str(self.timestamp) + str(self.data) + self.prev_hash
        return hashlib.sha256(content.encode()).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block("Genesis Block")

    def add_block(self, data):
        prev_hash = self.chain[-1].hash
        block = Block(data, prev_hash)
        self.chain.append(block)
        return block

    def verify(self):
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            if curr.hash != curr.calculate_hash():
                return False
            if curr.prev_hash != prev.hash:
                return False
        return True