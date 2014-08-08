# -*- coding: utf-8 -*-
__author__ = 'Guang Liu, UCBrowser, lg8585@gmail.com'
import scanf

def GetStartBaseInfo(event, parent_type):
  merged = {}
  merged["type"] = parent_type
  strs = event["Relative_Time"].split(":")
  time = int(strs[1]) * 60 + float(strs[2])
  merged['start_time'] = time
  merged["index"] = event["index"]
  merged["PID"] = event["PID"]
  merged["TID"] = event["TID"]
  merged["Path"] = event["Path"]
  return merged

def SplitDetail(detail):
  start = 0
  cur_name = ""
  obj = {}
  if detail is not None:
    for index in range(0, len(detail)):
      cur = detail[index:index+1]
      if cur == ":":
        cur_name = detail[start:index]
        start = index + 2
      elif cur == ",":
        if detail[index+1:index+2] == " ":
          value = detail[start:index]
          value = value.replace(",", "")
          obj[cur_name] = value
          cur_name = ""
          start = index + 2
      elif index == len(detail)-1:
        value = detail[start:]
        value = value.replace(",", "")
        obj[cur_name] = value
  return obj

def GetDetailInfo(event, parent_path):
  obj = {}
  obj["index"] = event["index"]
  obj["Duration"] = event["Duration"]
  obj["Operation"] = event["Operation"]
  obj["Result"] = event["Result"]
  if "Path" in event and event["Path"] is not None:
    if parent_path != "" and event["Path"] != parent_path and\
        event["Path"].find(parent_path) >= 0:
      obj["Path"] = event["Path"].replace(parent_path, "")
    else:
      obj["Path"] = event["Path"]

  op = event["Operation"]
  if op == "RegQueryValue":
    obj["Detail"] = event["Detail"]
  elif op == "ReadFile" or op == "WriteFile" or\
      op == "Load Image" or op == "DeviceIoControl":
    obj["Detail"] = SplitDetail(event["Detail"])

  time = 0
  try:
    time = float(obj["Duration"])
  except:
    pass
  return obj, time

def GetSecondsFromDatailTime(time):
    (hour, minute, sec) = scanf.sscanf(time, '%d:%d:%f')
    return sec + minute * 60 + hour*60*60

def ReadLengthToStr(size):
  return "%.3fMB" % (float(size)/(1024*1024))

def TimeToDesc(time):
  return "%.2f" % (float(time) / 1000)