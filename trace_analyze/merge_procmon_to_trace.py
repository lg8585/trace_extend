# -*- coding: utf-8 -*-
__author__ = 'Guang Liu, UCBrowser, lg8585@gmail.com'
import os
import json
import sys
import scanf
import random
import copy
import util
import getopt

from lxml import etree

time_convert = 1000000
file_ops = ["CreateFile", "ReadFile", "Load Image", "QueryOpen",
               "CreateFileMapping", "CloseFile", "IRP_MJ_CLOSE",
               "FileSystemControl","SetBasicInformationFile",
               "QueryBasicInformationFile",
               "QueryFileInternalInformationFile",
               "QueryNameInformationFile",
               "QueryStandardInformationFile","QueryAttributeTagFile",
               "WriteFile", "SetDispositionInformationFile",
               "QueryDirectory"
               ]
class AnalyzeProcMonResult():
  def __init__(self, key_time, pids, output_file):
    self.events = []
    self.key_time = key_time
    self.proc_mon_key_time = 0
    self.last_total_time = {}
    self.last_kernal_time = {}
    self.last_profiling_time = {}
    self.first_event_time = 0
    self.output_file = output_file
    self.pids = pids

  def analyze(self, xmlfile):
    tree = etree.parse(open(xmlfile,"rb"))
    root = tree.getroot()
    for child in root:
      if child.tag == "processlist":
        pass
      elif child.tag == "eventlist":
        self.analyze_event(child)

  def get_relative_time(self, time):
    (hour, minute, sec) = scanf.sscanf(time, '%d:%d:%f')
    time = sec + minute * 60 + hour*60*60
    ret = self.key_time + (time - self.proc_mon_key_time) * time_convert
    return int(ret)

  def get_full_time(self, time):
    (hour, minute, sec) = scanf.sscanf(time, '%d:%d:%f')
    return sec + minute * 60 + hour*60*60

  def get_random_id(self):
    return "0x%x" % (random.random() * 10000000000000000)

  def get_event_args(self, event):
    obj = {}
    obj["path"] = event["Path"]
    obj["time"] = event["Relative_Time"]
    obj["detail"] = event["Detail"]
    return obj

  def get_name_for_file_events(self, origin_event):
    split_names = ["\\User Data", "\\Chrome", "\\Chromium",
            "\\UCBrowser", "\\liebao"]
    if origin_event["Operation"] in file_ops:
      split = False
      for name in split_names:
        if origin_event["Path"].find(name) >= 0:
          split = True
          break
      if split:
        (drive, path) = os.path.splitdrive(origin_event["Path"])
        (path, filename)  = os.path.split(path)
        name = origin_event["Operation"] + " " + filename
      else:
        name = origin_event["Operation"] + " " + origin_event["Path"]
    else:
      name = origin_event["Operation"]
    return name
  def analyze_file_event(self, origin_event, pid):
    if origin_event["Duration"] == None:
      print "Duration None:", origin_event
      return

    rtime = self.get_relative_time(origin_event["Relative_Time"])

    if self.first_event_time == 0:
      self.first_event_time = rtime

    start_event = {}
    start_event["cat"] = "startup"
    start_event["name"] = self.get_name_for_file_events(origin_event)
    start_event["pid"] = pid
    start_event["tid"] = int(origin_event["TID"])
    start_event["ts"] = rtime
    start_event["id"] = self.get_random_id()
    duration = float(origin_event["Duration"])
    start_event["ph"] = "S"
    start_event['dur'] = duration * time_convert

    end_event = copy.deepcopy(start_event)
    end_event["ph"] = "F"
    end_event["ts"] = rtime + duration * time_convert
    end_event["args"] = self.get_event_args(origin_event)
    self.output_file.write(",")
    self.output_file.write(json.dumps(start_event))
    self.output_file.write(",")
    self.output_file.write(json.dumps(end_event))

  def analyze_process_profiling(self, origin_event, pid):
    rtime = self.get_relative_time(origin_event["Relative_Time"])
    details = util.SplitDetail(origin_event["Detail"])
    details["Private Bytes"] = int(details["Private Bytes"])
    details["Working Set"] = int(details["Working Set"])

    kernel_time = float(details["Kernel Time"].rstrip(" seconds"))\
                  * time_convert
    total_time = kernel_time +\
                 float(details["User Time"].rstrip(" seconds"))\
                 * time_convert
    del details["User Time"]
    del details["Kernel Time"]

    if pid in self.last_profiling_time:
      profiling_internal = rtime - self.last_profiling_time[pid]
    else:
      profiling_internal = rtime - self.first_event_time
    self.last_profiling_time[pid] = rtime

    if pid in self.last_kernal_time:
      tmp = kernel_time
      kernel_time = kernel_time - self.last_kernal_time[pid]
      self.last_kernal_time[pid] = tmp
      tmp = total_time
      total_time = total_time - self.last_total_time[pid]
      self.last_total_time[pid] = tmp
    else:
      self.last_kernal_time[pid] = kernel_time
      self.last_total_time[pid] = total_time

    details["Kernel CPU Usage"] = kernel_time / profiling_internal
    details["Total CPU Usage"] = total_time / profiling_internal

    for k, v in details.items():
      event = {}
      event["cat"] = "perf"
      event["ph"] = "C"
      event["ts"] = rtime
      event["pid"] = pid
      event["tid"] = int(origin_event["TID"])
      event["name"] = k
      args = {}
      args["value"] = v
      event["args"] = args
      self.output_file.write(",")
      self.output_file.write(json.dumps(event))

  def analyze_event(self, child):
    origin_event_list = []
    index = 0
    count = len(child)
    for node in child:
      index = index + 1
      if index % 20000 == 0:
        print "Prepare Event %d/%d" % (index, count)
      node_event = {}
      for content in node:
        node_event[content.tag] = content.text

      pid = int(node_event["PID"])
      if pid not in self.pids:
        continue

      origin_event_list.append(node_event)

      if node_event["Event_Class"] == "Process" and\
          node_event["Operation"] == "Process Create" and\
          node_event["Detail"].find("--type=renderer") > 0 and\
          node_event["Detail"].find("--type=gpu-process") == -1 and\
          node_event["Detail"].find("--fast-process-launcher") == -1:
        if self.proc_mon_key_time == 0:
          self.proc_mon_key_time = \
            self.get_full_time(node_event["Relative_Time"])
          print node_event
          print "proc_mon_key_time:", self.proc_mon_key_time

    index = 0
    count = len(origin_event_list)
    for origin_event in origin_event_list:
      index = index + 1
      if index % 4000 == 0:
        print "Process Event %d/%d" % (index, count)

      pid = int(origin_event["PID"])

      if origin_event["Event_Class"] in\
          ["File System", "Process", "Registry", "Network"]:
        self.analyze_file_event(origin_event, pid)
      elif origin_event["Event_Class"] == "Profiling" and\
              origin_event["Operation"] == "Process Profiling":
        self.analyze_process_profiling(origin_event, pid)

class AnalyzeTrace():
  def __init__(self, trace_file):
    self.obj = json.load(file(trace_file))

  def get_key_info(self):
    keytime = 0
    pids = {}
    for event in self.obj["traceEvents"]:
      if event["name"] == "StartProcessWithAccess":
        if event["args"]["extra"] == "renderer" and keytime == 0:
          print event
          keytime = event["ts"]
      if event["pid"] not in pids:
        pids[event["pid"]] = 1
    print "gpu-process start time", keytime
    print "pids", pids
    return keytime, pids

  def add_events(self, events):
    self.obj["traceEvents"].extend(events)

  def output(self, out_file):
    json.dump(self.obj, open(out_file,'w+'))

def Analyze(startup_file, shutdown_file, proc_mon_file, out_file):
  startup = AnalyzeTrace(startup_file)
  startup_text = open(startup_file,"r").read()
  output_file = open(out_file,"w")
  print "write startup tracing file"
  output_file.write(startup_text[:len(startup_text)-2])

  print "merge procmon file"
  keytime, pids = startup.get_key_info()
  proc_mon = AnalyzeProcMonResult(keytime, pids, output_file)
  proc_mon.analyze(proc_mon_file)

  print "write shutdown tracing file"
  try:
    shutdown = AnalyzeTrace(shutdown_file)
    for event in shutdown.obj["traceEvents"]:
      output_file.write(",")
      output_file.write(json.dumps(event))
  except:
    print "write shutdown tracing file failed."
  output_file.write("]}")
  output_file.close()

if __name__ == '__main__':
  opts, args = getopt.getopt(sys.argv[1:], "", ["startup-file=",
                          "shutdown-file=",
                          "procmon-file=",
                          "output-file="])

  for key, value in opts:
    if key == "--startup-file":
      startup_file = value
    if key == "--shutdown-file":
      shutdown_file = value
    if key == "--procmon-file":
      proc_mon_file = value
    if key == "--output-file":
      out_file = value

  Analyze(startup_file, shutdown_file, proc_mon_file, out_file)









