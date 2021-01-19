import socket
import threading
import pickle
from Crypto.PublicKey import RSA
import hashlib
from datetime import datetime


class block:
    def __init__(self, timestamp, transaction, previousHash=' '):
        self.timestamp = timestamp
        self.transaction = transaction
        self.previousHash = previousHash
        self.nonce = 0
        self.hash = self.CalculateHash()

    def CalculateHash(self):
        st = ''
        for tr in self.transaction:
            st += tr.sender
            st += tr.receiver
            st += str(tr.amount)
        ch = str(self.timestamp)+self.previousHash+str(self.nonce)+st
        return hashlib.sha256(bytes(ch, "utf-8")).hexdigest()

    def mineBlock(self, difficulty):
        i, a = 0, ''
        while i < difficulty:
            a += '0'
            i += 1
        while self.hash[:difficulty] != a:
            self.nonce += 1
            self.hash = self.CalculateHash()
        print("Block mined")

    def hasValidTransaction(self):
        for tr in self.transaction:
            if(not tr.isValid()):
                return False
        return True

    def __repr__(self):
        return "\t\t **** BLOC START ****\n" + """Timestamp: {} \n Transaction: {} \n PreviousHash: {}
                \n Nonce: {} \n Hash: {} \n""".format(self.timestamp,
                self.transaction, self.previousHash, self.nonce, self.hash)+"\n \t\t**** BLOC END ****"


class Blockchain:
    def __init__(self):
        self.difficulty = 3
        self.chain = [self.GenerateGenesis()]
        self.pendingTransaction = []
        self.reward = 100

    def GenerateGenesis(self):
        nouB = block(datetime.now(), [Transaction('', 'None', 0)], '')
        nouB.mineBlock(self.difficulty)
        return nouB

    def getLastBlock(self):
        return self.chain[len(self.chain)-1]

    def minePendingTransaction(self, addrMiner):
        nouvBlock = block(datetime.now(), self.pendingTransaction, self.getLastBlock().hash)
        nouvBlock.mineBlock(self.difficulty)
        self.chain.append(nouvBlock)

        self.pendingTransaction = [Transaction("", addrMiner, self.reward)]

    def addTransaction(self, transaction):
        if not self.checkBalance(transaction):
            print("Solde Insuffisannt")
            return False
        if not transaction.isValid():
            print("Transaction invalideee")
            return False
        elif not transaction.receiver:
            print("renseigner receiver")
            return False
        self.pendingTransaction.append(transaction)
        return True

    def getBalance(self, addr):
        if addr == '':
            return 100000
        balance = 0
        for ch in self.chain:
            for tr in ch.transaction:
                if tr.sender == addr:
                    balance -= tr.amount
                elif tr.receiver == addr:
                    balance += tr.amount
        return balance

    def checkBalance(self, transaction):
        balance = self.getBalance(transaction.sender)
        if balance >= transaction.amount:
            return True
        return False

    def isValid(self):
        i = 1
        while(i < len(self.chain)):
            currB = self.chain[i]
            prevB = self.chain[i-1]
            if not currB.hasValidTransaction():
                return False
            if currB.hash != currB.CalculateHash():
                return False
            if currB.previousHash != prevB.hash:
                return False
            i += 1

    def __repr__(self):
        print("\n [***********CHAIN START***********]\n")
        for bl in self.chain:
            print(bl)
        print("\n [***********CHAIN START***********]\n")
        return ''


class Transaction:
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount

    def CalculateHash(self):
        ch = self.sender+self.receiver+str(self.amount)
        return hashlib.sha256(bytes(ch, "utf-8")).digest()

    def signTransaction(self, key):
        if key.publickey().exportKey().decode('utf-8') != self.sender:
            print("Erreur de signature")
            return
        hashTr = int.from_bytes(self.CalculateHash(), byteorder='big')
        signature = pow(hashTr, key.d, key.n)
        self.signature = signature

    def check_signature(self):
        keypub = RSA.importKey(self.sender, passphrase=None)
        hashTr = int.from_bytes(self.CalculateHash(), byteorder='big')
        signature = pow(self.signature, keypub.e, keypub.n)
        if hashTr == signature:
            return True
        return False

    def isValid(self):
        if self.sender == '':
            return True
        if not self.signature:
            return False
        if len(hex(self.signature)) == 0:
            return False
        return True

    def __repr__(self):
        return '\n ### sender: {}---> receiver: {} amount:{}\n'.format(self.sender,self.receiver,self.amount)


class P2P:
    def __init__(self):
        self.CONNECTION = []
        self.keyPair = RSA.generate(1024)
        self.PUBLIC_ADDR = self.keyPair.publickey().exportKey().decode('utf-8')
        self.PORT = 5050
        self.HEADER = 64
        self.FORMAT = 'utf-8'
        self.SERVER = socket.gethostbyname(socket.gethostname())
        print(self.SERVER)
        self.sc_pr = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        ADDR = (self.SERVER, self.PORT)
        self.sc_pr.bind(ADDR)
        self.blck = Blockchain()

    def start(self):
        self.sc_pr.listen()
        while True:
            conn, addr = self.sc_pr.accept()
            self.CONNECTION.append(conn)
            print("[NOUVEAU NOEUD CONNECTÉ]: ", addr)
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()

    def message_handle(self, msg, conn, addr):
        if msg['type'] == "Transaction":
            if msg["body"].check_signature():
                if self.blck.addTransaction(msg["body"]):
                    self.blck.minePendingTransaction(self.PUBLIC_ADDR)
                    message = {"type": "RBlockchain", "body": self.blck}
                    self.broadcastMessage(message)
        if msg["type"] == "OBlockchain":
            self.blck.addTransaction(Transaction('', msg["body"], 200))
            self.blck.minePendingTransaction(self.PUBLIC_ADDR)
            message = {"type": "RBlockchain", "body": self.blck}
            self.broadcastMessage(message)
        if msg["type"] == "RBlockchain":
            self.blck.replaceChain(msg["body"])

    def broadcastMessage(self, msg):
        for conn in self.CONNECTION:
            self.sent(msg, conn)

    def sent(self, msg, conn):
        message = pickle.dumps(msg)
        msg_length = len(message)
        send_length = str(msg_length).encode(self.FORMAT)
        send_length += b' ' * (self.HEADER - len(send_length))
        conn.send(send_length)
        conn.send(message)

    def handle_client(self, conn, addr):
        while True:
            msg_length = conn.recv(self.HEADER).decode(self.FORMAT)
            msg_length = int(msg_length)
            msg = conn.recv(msg_length)
            msg = pickle.loads(msg)
            self.message_handle(msg, conn, addr)





 https://us04web.zoom.us/j/75215422836?pwd=QWJobnJlVmp4VUhoTGJ4cm9lVzB6Zz09


if __name__ == '__main__':
    p2p = P2P()
    print(p2p.blck)
    p2p.start()
