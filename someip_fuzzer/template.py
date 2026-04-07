from scapy.all import *
from someip_fuzzer.config import config
from someip_fuzzer.log import log_info
import binascii
import json
import pprint

load_contrib("automotive.someip")

class Template():

    def read_capture(self):    # 패킷(PCAP) 읽는 함수
        plist = sniff(filter=config["Fuzzer"]["Filter"], prn=self.log_packet, offline=config["Fuzzer"]["Trace"])
        return plist

    @staticmethod
    def log_packet(packet):   # trace 읽을때 어떤 패킷이 들어왔는지 간단히 보여주는 용도.
        log_info(packet.summary())

    def create_template(self, packets):   # 패킷에서 필드값을 뽑아 템플릿 dict를 만드는 함수.
        template = {}
        while len(packets):
            packet = packets.pop(0)
            layer = [layer.name for layer in self.__count_layers(packet)]
            log_info(layer)
            payload = packet.getlayer(3) # gets SOME/IP layer and below
            outgoing = packet["UDP"].dport == int(config["Service"]["Port"])
            self.__add_to_template(template, outgoing, payload)
        return template

    def save_template(self, template):   # 메모리 안의 템플릿 dict를 json 파일로 저장하는 함수
        template_json = []
        for key, value in template.items():
            template = {
                "outgoing": key[0], # true, false
                "layer": key[1], # SOMEIP, SOMEIP-SD, etc.
                "fields": value["fields"] # srv_id, sub_id, method_id, event_id, etc.
            }
            template_json.append(template)
        with open(config["Fuzzer"]["Template"], "w") as outfile:
            json.dump(template_json, outfile, indent = 4, cls=TemplateEncoder)

    def print_template(self, template):   # 저장없이 화면에 json 형태로 출력하는 디버깅용 함수
        template_json = []
        for key, value in template.items():
            template = {
                "outgoing": key[0],
                "layer": key[1],
                "fields": value["fields"]
            }
            template_json.append(template)
        print(json.dumps(template_json, default=str, indent=4, sort_keys=False))

    def read_template(self):   # 저장된 json 파일을 읽고 메모리에 dict 형태로 복원
        with open(config["Fuzzer"]["Template"], "r") as infile:
            template_json = json.load(infile)
        template = {}
        for item in template_json:
            template[(item["outgoing"], item["layer"])] = {"fields": item["fields"]}
        return template

    def __add_to_template(self, template, outgoing, payload):   # 방향 + 레이어 종류를 기준으로 템플릿 분
        key = (outgoing, type(payload).__name__) # example: (True, SOMEIP)
        if key not in template:
            template[key] = {}
        paket_layers = [layer.name for layer in self.__count_layers(payload)]
        template_layer = template[key]
        if "fields" not in template_layer:
            fields = {}
        for paket_layer in paket_layers:
            for name, value in payload.getlayer(paket_layer).fields.items():
                fields[name] = {
                    "values": set(),
                    "type": type(payload[paket_layer].get_field(name)).__name__, # ugly, but we need to get Scapy data types
                    "fuzzing": {"fuzzer": None},
                }
                template_layer["fields"] = fields
            try:
                for name, value in payload.getlayer(paket_layer).fields.items():
                    template_layer["fields"][name]["values"].add(value) # add protocol layer field value, e.g. srv_id -> 4660
            except TypeError:
                print("Unhashable type") 

    def __count_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1

class TemplateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return binascii.hexlify(obj).decode("utf-8")
        return json.JSONEncoder.default(self, obj)
