from scapy.all import *
from someip_fuzzer.config import config
from someip_fuzzer.log import log_info
from someip_fuzzer.types import *
from queue import Queue
import threading
import time

load_contrib("automotive.someip") # 자동차용 SOME/IP 프로토콜 사용

class Heartbeat(threading.Thread):   # fuzzer와 마찬가지로 스레드 클래스rom scapy.all import *
from someip_fuzzer.config import config
from someip_fuzzer.log import log_info
from someip_fuzzer.types import *
from queue import Queue
import threading
import time

load_contrib("automotive.someip") # 자동차용 SOME/IP 프로토콜 사용

class Heartbeat(threading.Thread):   # fuzzer와 마찬가지로 스레드 클래스

    def __init__(self, excq):
        super().__init__()
        self.excq = excq
        self.shutdown = threading.Event()
       
    def run(self):   # 자동으로 실행되는 메인루프
        log_info("Heartbeat is started")
        while not self.shutdown.is_set():
            try:
                time.sleep(3) # 3초 주기 heartbeat
                self.check()
            except PermissionError:   # 패킷 전송 시 권한 문제가 생겼을 때 처리하는 부분
                self.excq.put(NoSudoError("Permission as sudo required to send SOME/IP pakets"))
        log_info("Heartbeat is stopped")

    def check(self):  # 실제 heartbeat 패킷을 만들어보내는 함수
        try:
            i = IP(src=config["Client"]["Host"], dst=config["Service"]["Host"])
            u = UDP(sport=config["Client"].getint("Port"), dport=config["Service"].getint("Port"))
            sip = SOMEIP()
            sip.iface_ver = 0
            sip.proto_ver = 1
            sip.msg_type = "REQUEST"
            sip.retcode = "E_OK"
            sip.msg_id.srv_id = 0x1234
            sip.msg_id.sub_id = 0x0
            sip.msg_id.method_id=0x0421
            sip.req_id.client_id = 0x1313
            sip.req_id.session_id = 0x0010

            # 위는 기존 헤더 양식을 따른 것이라 변화 없고.
            # 여기서 요청 payload로 "ping" 문자열을 넣음
            # 살아있으면 ping에 대한 응답을 달라는 
            sip.add_payload(Raw ("ping"))
            paket = i/u/sip   # Raw("ping")
            res = sr1(paket, retry=0, timeout=3, verbose=False) 

            # ping 보내고 3초 안에 답 없으면 fail
            if res == None:
                raise NoHostError("No response received from SOME/IP host")

            # 응답이 오더라도 응답의 payload 마지막 4바이트가 "pong"이 아니면 heartbeat 실패로 봄.
            # 아마 scapy 내부적으로 ping 문자열에 대해 pong으로 응답하도록 설계된듯.
            if res[Raw].load[-4:] != bytes("pong", "utf-8"):
                raise NoHeartbeatError("No heartbeat found on SOME/IP service")

        # 이 두 예외는 heartbeat 스레드에서 처리하고 않고, 큐에 넣어 main에게 전달함.
        # 전체 흐름 제어를 main에서 함. 
        except (NoHostError, NoHeartbeatError) as exc:
                self.excq.put(exc)
