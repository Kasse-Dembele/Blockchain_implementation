import socket
import pickle
from Crypto.PublicKey import RSA
import hashlib
from datetime import datetime
import threading


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
    """def __init__(self):
        self.chain = [self.GenerateGenesis()]
        self.difficulty = 3
        self.pendingTransaction = []
        self.reward = 100"""

    def getLastBlock(self):
        return self.chain[len(self.chain)-1]

    """def minePendingTransaction(self, addrMiner):
        nouvBlock = block(datetime.now(), self.pendingTransaction, self.getLastBlock().hash)
        nouvBlock.mineBlock(self.difficulty)
        self.chain.append(nouvBlock)

        self.pendingTransaction = [Transaction("", addrMiner, self.reward)]"""

    def addTransaction(self, transaction):
        if not self.checkBalance(transaction):
            print("Solde Insuffisannt")
            return
        if not transaction.isValid():
            print("Transaction invalideee")
            return
        elif not transaction.receiver:
            print("renseigner receiver")
            return
        if not transaction.check_signature:
            print("Mauvaise signature")
        self.pendingTransaction.append(transaction)

    def getBalance(self, addr):
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
        return True

    def replaceBlck(self, newChain):
        if len(newChain) > len(self.chain):
            if newChain.isValid:
                self.chain = newChain.chain

    def __repr__(self):
        print("\n [***********CHAIN START***********]\n")
        for bl in self.chain:
            print(bl)
        print("\n [***********CHAIN END***********]\n")
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
        return '### sender: {}---> receiver: {} amount:{}\n'.format(self.sender,self.receiver,self.amount)


class Node(object):
    def __init__(self):
        self.keyPair = RSA.generate(1024)
        self.PUBLIC_ADDR = self.keyPair.publickey().exportKey().decode('utf-8')
        SERVER = '192.168.1.108'
        PORT = 5050
        self.HEADER = 64
        ADDR = (SERVER, PORT)
        self.FORMAT = 'utf-8'
        self.sockClient = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        self.sockClient.connect(ADDR)
        thread = threading.Thread(target=self.handle_server)
        thread.start()

    def getBlockchain(self):
        message = {"type": "OBlockchain", "body": self.PUBLIC_ADDR}
        self.sent(message)

    def handle_server(self):
        connected = True
        while True:
            msg_length = self.sockClient.recv(self.HEADER).decode(self.FORMAT)
            msg_length = int(msg_length)
            msg = self.sockClient.recv(msg_length)
            msg = pickle.loads(msg)
            self.message_handle(msg)

    def sent(self, msg):
        message = pickle.dumps(msg)
        msg_length = len(message)
        send_length = str(msg_length).encode(self.FORMAT)
        send_length += b' ' * (self.HEADER - len(send_length))
        self.sockClient.send(send_length)
        self.sockClient.send(message)
        """thread = threading.Thread(target=self.handle_server)
        thread.start()"""

    def message_handle(self, msg):
        if msg['type'] == "Transaction":
            self.blck.addTransaction(msg["body"])

        if msg["type"] == "OBlockchain":
            message = {"type": "RBlockchain", "body": self.blck}
            self.sent(message)

        if msg["type"] == "RBlockchain":
            self.blck = msg["body"]


def menu(node):
    v = True
    while v:
        print('0:Pour quitter')
        print('1:Effectuer une transaction')
        print('2:Consulter solde')
        print('3:Afficher la chain')
        print('4:Afficher ma clé publique')
        ch = int(input('Entrez votre choix: '))
        if(ch == 1):
            receiver = input('Entrez le destinataire: ')
            amount = int(input('Entrez le montant: '))
            tr1 = Transaction(node.PUBLIC_ADDR, receiver, amount)
            tr1.signTransaction(node.keyPair)
            message = {"type": "Transaction", "body": tr1}
            node.sent(message)
        elif ch == 2:
            print("Votre solde est de: ", node.blck.getBalance(node.PUBLIC_ADDR), "dh")
        elif ch == 3:
            print(node.blck)
        elif ch == 4:
            print("Ma clé public est:", node.PUBLIC_ADDR)
        elif ch == 0:
            v = False


if __name__ == '__main__':
    node = Node()
    node.getBlockchain()
    menu(node)
