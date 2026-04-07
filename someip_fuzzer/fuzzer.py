from scapy.all import *
from someip_fuzzer.config import config
from someip_fuzzer.log import log_info
from someip_fuzzer.types import *
from queue import Queue
import binascii  # hex 문자열 -> 실제 bytes 변
import random
import threading
import time
import subprocess   # 외부 퍼저인 radamsa 호출 위해 사용. 즉 내부에 mutation 로직 없음.

class Fuzzer(threading.Thread):    # 일반 클래스가 아니라, 스레드처럼 실행되는 클래스

    def __init__(self, index, excq, template, targets):  
        super().__init__()
        self.index = index # 스레드 번호
        self.excq = excq # 예외 큐
        self.template = template # 불러온 템플릿 딕셔너리 저장
        self.targets = targets # 퍼징 타깃 정보
        self.shutdown = threading.Event() # 종료 플래그
    
    def run(self):
        log_info("Thread #{} is started".format(self.index))
        while not self.shutdown.is_set():   # 종료 플래그가 켜지기 전까지 계속 반복해라.
            time.sleep(1) # this value must be set according to the available bandwidth
            value = self.prepare() # fuzzed payload를 준비
            
            self.send(value)
        log_info("Thread #{} is stopped".format(self.index))

    def prepare(self):   # 퍼징에 사용할 입력값 하나를 준비하는 함수 
        if self.shutdown.is_set():
            return

        #템플릿에서 seed 하나 고르고 radamsa로 mutation해서 value에 저장
        fields = self.template[(True, config["Fuzzer"]["Layer"])]["fields"]
        target = self.targets[0]
        index = random.choice(range(len(fields[target]["values"])))
        value = fields[target]["values"][index]
        
        # 외부 프로그램 radamsa 실행
        p = subprocess.Popen(
            ["radamsa"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        if isinstance(value, str): # 문자열 hex이라면 -> 실제 bytes로 바꾸는 구간 
            value_convert = binascii.unhexlify(value) # convert hex -> 48656c6c6f205365727669636521 to ascii -> b'Hello Service!'
        else: # 문자열 아니고 bytes나 숫자면 그대로 사용
            value_convert = value

        # 여기가 핵심
        # radamsa 프로세스에 value_convert를 입력으로 넣고 출력을 stdout으로 받아옴
        # 입력 : 원본 seed payload
        # 출력 : radamsa가 변형한 fuzzed payload
        value_fuzz = p.communicate(input=value_convert)[0]

        # config.ini에서 history == yes면 현재 결과를 다음 시드로 저장함.
        if config["Fuzzer"]["History"] == "yes":
            log_info("Saving current fuzzing value as next seed")

            # 현재 시드를 변이값으로 덮어씀
            # seed를 누적 변이하는 구조
            fields[target]["values"][index] = value_fuzz
        return value_fuzz # 여기서 fuzzed payload를 반환함. 이제 이걸 send에 넘김

    def send(self, value): # 변이된 payload를 some/ip 패킷에 실어서 서버로 보내는 역할
        log_info("Sending: {}".format(value))
        # IP 헤더 생성.  출발지 ip : 클라 호슽트, 목적지 ip : 서비스 호스트 (서버 호스트)
        i = IP(src=config["Client"]["Host"], dst=config["Service"]["Host"])
        # UDP 헤더 생성 source port, destination port
        u = UDP(sport=config["Client"].getint("Port"), dport=config["Service"].getint("Port"))
        sip = SOMEIP()  # SOME/IP 헤더 객체 생성 -> scapy의 someip layer를 씀
        sip.iface_ver = 0
        sip.proto_ver = 1
        sip.msg_type = "REQUEST"
        sip.retcode = "E_OK"
        sip.msg_id.srv_id = 0x1234
        sip.msg_id.sub_id = 0x0
        sip.msg_id.method_id=0x0421
        sip.req_id.client_id = 0x1313
        sip.req_id.session_id = 0x0010
        # 이로서 헤더값들은 템플릿에서 읽어오는게 아니고
        # 코드에 '하드코딩'된 값들임을 알게됌.
        
        sip.add_payload(Raw (value))  # 변이된 payload bytes를 SOMEIP 뒤에 raw 데이터로 붙임.
        # 이게 실제 공격
        
        paket = i/u/sip  # 계층을 쌓아서 패킷 완성 
        res = sr1(paket, retry=0, timeout=1, verbose=False)
        # sr1() 함수는 패킷을 실제로 보내고 응답 1개를 기다림 
