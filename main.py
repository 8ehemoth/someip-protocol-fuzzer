from someip_fuzzer.config import config
from someip_fuzzer.fuzzer import Fuzzer
from someip_fuzzer.heartbeat import Heartbeat
from someip_fuzzer.log import log_info, log_error
from someip_fuzzer.template import *
from someip_fuzzer.types import *
from queue import Queue
import signal
import time

def generate_template():
    generator = Template()
    packets = generator.read_capture()
    trace = generator.create_template(packets)
    generator.save_template(trace)
    log_info("Printing JSON dump")
    generator.print_template(trace)

def import_template():
    generator = Template()
    trace = generator.read_template()
    return trace

def shutdown(signum, frame):
    raise ServiceShutdown("Caught signal %d" % signum)

def main():

    # 프로그램이 종료될 때 바로 죽지 말고, 
    # shutdown()을 통해 ServiceShutdown 예외를 발생시켜 메인 흐름으로 종료 사실을 전달해라
    # SIGTERM: 운영체제나 다른 프로세스가 “정상 종료해라” 하고 보내는 신호
    # SIGINT: 사용자가 터미널에서 Ctrl + C 눌렀을 때 들어오는 신호
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # excq : 스레드들이 메인 스레드에게 예외 처리를 전달하기 위한 큐
    # target은 실제로 퍼징할 필드 목록을 저장하는 리스트
    # threads는 실행할 스레드 객체들을 저장하는 리스트 ex) heartbeat 스레드, fuzzer 스레드
    excq = Queue()
    targets = []
    threads = []

    template = import_template()
    # import_template() 함수를 통해 config.ini에 template 경로에 있는 json 문자열을 파이썬 자료형으로 바꿈
    
    fields = template[(True, config["Fuzzer"]["Layer"])]["fields"].items()
    # 위 함수로 인해 Layer가 SOMEIP가 맞다면 -> fields 값을 반환해서 튜플 키 기반 딕셔너리로 바꿈
    # (순회하기 좋게 만들기 위해)
    
    for fieldname, fieldvalues in fields:   # 템플릿 안의 각 필드를 하나씩 순
        fuzzer = fieldvalues["fuzzing"]["fuzzer"]  # fuzzer 종류 : "None"이면 fuzz 안하고, "radamsa"면 변이 
        if fuzzer is not None:    # 퍼저가 지정된 필드만 고르기
            targets.append((fieldname, fuzzer))      # ex) ("load", "radamsa") 처럼 무슨 필드를 어떤 방식으로 퍼즈할지
            log_info("Fuzzing protocol layer '{}' on protocol field '{}'".format(config["Fuzzer"]["Layer"], fieldname))
            # 이건 로그를 출력하는 함수. SOMEIP의 어느 필드를 퍼즈 타겟으로 잡았다.

    # 만약 config.ini에서 Mode가 replay라면 실행하겠다.
    if config["Fuzzer"]["Mode"] == "replay":
        try:
            # heartbeat 스레드 생성
            threads.append(Heartbeat(excq))
            # fuzzing 대상 필드 수만큼 fuzzer 스레드 생성
            for i in range(len(targets)):
                threads.append(Fuzzer(i, excq, template, targets[i]))
            # 모든 스레드 시작
            for t in threads:
                t.start()
            # 서브 스레드에서 큐에 예외를 넣었는지 계속 확
            while True:
                if excq.qsize() != 0:
                    raise excq.get()
        # NoHostError : 서버 자체에 닿지 않음
        # NoHeartbeatError : heartbeat 응답이 이상함
        # NoSudoError : 권한 문제
        except (NoHostError, NoHeartbeatError, NoSudoError) as exc:
            log_error(exc)
        except ServiceShutdown as msg:
            log_info(msg)

        # 무조건 실행되는 정리 구문
        finally:
            for t in threads:
                t.shutdown.set()
                t.join()
            log_info("Exiting main()")
        # 각 스레드에 종료 신호 보내고, 스레드가 빌때까지 기다리고 로그 출력
    # Mode 중에 하나인데 아직 미구현되어있음.
    elif config["Fuzzer"]["Mode"] == "live":
        pass

if __name__ == "__main__":
    main()
