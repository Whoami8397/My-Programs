import re
import pandas as pd
from itertools import islice
import schedule
import time
counter = 0; num = 0
pattern = r"(?P<Time>[0-9]{2}\:[0-9]{2}:[0-9]{2})\.\d+\s\w+\s(?P<DeviceAdd>\b"\
          r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\.\d+\s\>\s(?P<AgentAdd>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\.\w+\:\s"\
          r"(?P<logType>\w+\s\w+\.\w+)\,\s\w+\:\s(?P<length>\d+)"
pattern2 = r"^\..*\<(?P<Severity>\d+)\>\w+\=" \
           r"(?P<date>\d{4}\-\d{2}\-\d{2})\s\w+\=" \
           r"(?P<time>[0-9]{2}\:[0-9]{2}:[0-9]{2})\s\w+\=" \
           r"(?P<log_id>\d+)\s\w+\=(?P<msg_id>\d+)\s\w+\=" \
           r"(?P<device_id>.+(?=\svd))\s\w+\=\"(?P<vd>\w+)\"\s\w+\=\"" \
           r"(?P<timezone>.+(?=\"\stimezone))\"\s\w+\=\"" \
           r"(?P<timezone_dayst>.+(?=\"\stype))\"\s\w+\=(?P<type>\w+)\s\w+\=" \
           r"(?P<pri>\w+)\s\w+\=\"(?P<main_type>\w+\s\w+)\"" \
           r"\s\w+\=\"(?P<sub_type>\w+\s\w+).*\"" \
           r".*severity_level\=(?P<s_level>\w+)" \
           r".*src\=(?P<src>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\s\w+\=(?P<SRC_Port>\d+)" \
           r".*dst\=(?P<dst>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\s\w+\=(?P<DST_Port>\d+)" \
           r"\s\w+\=(?P<method>\w+).*http_host\=\"(?P<http_host>\w+\.\w+\.\w+)\".*"\
           # r"(?P<main_type>\w+)\"\s\w+"
            # (?P<service>.+(?=\sstatus))\s\w+\=" \
           # r"(?P<status>\w+)\s\w+\=(?P<reason>\w+)\s\w+\=(?P<policy>\w+)\s\w+\=" \
           # r"(?P<orginal_src>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\s\w+\=" \
           # r"(?P<src>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\s\w+\=(?P<src_port>\d+)\s\w+\=" \
           # r"(?P<dst>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\s\w+\=(?P<dst_port>\d+)\s\w+\=" \
           # r"(?P<http_request_time>\d)\s\w+\=(?P<http_response_time>\d)\s\w+\=" \
           # r"(?P<http_request_bytes>\d+)\s\w+\=(?P<http_response_bytes>\d+)\s\w+\=" \
           # r"(?P<http_method>\w+)\s\w+\=(?P<http_url>.+(?=\shttp_agent))\s\w+\=" \
           # r"(?P<http_agent>.+(?=\shttp_retcode))\s\w+\=(?P<http_retcode>\d+)\s\w+\=\"" \
           # r"(?P<msg>.+(?=\"\soriginal_srccountry))\"\s\w+\=\"" \
           # r"(?P<original_srccountry>\w+)\"\s\w+\=\"(?P<srccountry>\w+)\"\s\w+\=\"" \
           # r"(?P<content_switch_name>\w+)\"\s\w+\=\"(?P<server_pool_name>.+" \
           # r"(?=\"\shttp_host))\"\s\w+\=\"(?P<http_host>.+(?=\"\suser_name))\"\s\w+\=\"" \
           # r"(?P<user_name>\w+)\"\s\w+\=\"(?P<http_refer>.+(?=\"\shttp_version))\"\s\w+\=\"" \
           # r"(?P<http_version>.+(?=\sdev_id))\s\w+\=(?P<dev_id>\w+)\s\w+\=\"" \
           # r"(?P<cipher_suite>.+(?=\"))"
def parser():
    fname= "D:\\logg.txt"
    global num, counter
    with open (fname) as myFile:
        TIME = []
        DeviceAdd = []
        AgentAdd = []
        logType = []
        length = []
        Severity = []
        date = []
        time = []
        log_id = []
        msg_id = []
        device_id = []
        vd = []
        timezone = []
        timezone_dayst = []
        type = []
        subtype = []
        pri = []
        main_type = []
        s_level = []
        src = []
        SRC_Port = []
        dst = []
        DST_Port = []
        method = []
        http_host = []

        comp = re.compile("(%s|%s)" % (pattern, pattern2))
        for num, line in enumerate(myFile, 1):
            for m in re.finditer(comp, line):
                TIME.append(m.group("Time"))
                DeviceAdd.append(m.group("DeviceAdd"))
                AgentAdd.append(m.group("AgentAdd"))
                logType.append(m.group("logType"))
                length.append(m.group("length"))
                Severity.append(m.group("Severity"))
                date.append(m.group("date"))
                time.append(m.group("time"))
                log_id.append(m.group("log_id"))
                msg_id.append(m.group("msg_id"))
                device_id.append(m.group("device_id"))
                vd.append(m.group("vd"))
                timezone.append(m.group("timezone"))
                timezone_dayst.append(m.group("timezone_dayst"))
                type.append(m.group("type"))
                subtype.append(m.group("sub_type"))
                pri.append(m.group("pri"))
                # proto.append(m.group("proto"))
                main_type.append(m.group("main_type"))
                s_level.append(m.group("s_level"))
                src.append(m.group("src"))
                SRC_Port.append(m.group("SRC_Port"))
                dst.append(m.group("dst"))
                DST_Port.append(m.group("DST_Port"))
                method.append(m.group("method"))
                http_host.append(m.group("http_host"))
                # service.append(m.group("service"))
                # status.append(m.group("status"))
                # reason.append(m.group("reason"))
                # policy.append(m.group("policy"))
                # original_srccountry.append(m.group("original_srccountry"))
        counter+=num

    df = pd.DataFrame({'DATE':list(filter(None, TIME)),
                       'Device_IP':list(filter(None, DeviceAdd)),
                       'AgentAdd':list(filter(None, AgentAdd)),
                       'logType':list(filter(None, logType)),'length':list(filter(None, length)),
                       'Severity':list(filter(None, Severity)),
                       'date':list(filter(None, date)),
                        'time': list(filter(None, time)),
                       'log_id':list(filter(None, log_id)),
                       'msg_id':list(filter(None, msg_id)),
                       'device_id': list(filter(None, device_id)),
                        'vd':list(filter(None, vd)),
                       'timezone':list(filter(None, timezone)),
                       'timezone_dayst':list(filter(None, timezone_dayst)),
                       'type':list(filter(None, type)),
                       'subtype': list(filter(None, subtype)),
                       'pri':list(filter(None, pri)),
                       'main_type':list(filter(None, main_type)),
                       'impact': list(filter(None, s_level)),
                       'SRC_IP': list(filter(None, src)),
                       'SRC_Port': list(filter(None, SRC_Port)),
                       'DST_IP': list(filter(None, dst)),
                       'DST_Port': list(filter(None, DST_Port)),
                       'HTTP_Method': list(filter(None, method)),
                       'http_host': list(filter(None, http_host))
                       # 'proto':list(filter(None, proto)), 'service':service,'status':status,'reason':reason,
                       # 'policy':policy, 'original_srccountry':original_srccountry
                       })
    df.to_csv('FW_MyFile.csv', mode='w', index=False, header=True)
    myFile.close()
# schedule.every(1).minutes.do(parser)
# while True:
#     schedule.run_pending()
#     time.sleep(1)
parser()
