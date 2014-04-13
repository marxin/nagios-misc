#!/usr/bin/env python

import os
import time

from optparse import OptionParser

class SnmpCheck:
  def get_value(self, host, oid, password):
    r = os.popen('snmpget -u public -v 3 -a MD5 -A %s -l authPriv -x DES -X %s %s %s' % (password, password, host, oid))
    return r.readlines()

  def get_status(self, value, w, c):
    if value < w:
      return 0
    elif value < c:
      return 1
    else:
      return 2

  def build_result(self, status, format, value):
    preambule = ['OK', 'WARNING', 'CRITICAL'][status]
    return (status, ('%s %s - ' + format) % (preambule, self.name.upper(), value))

class CpuSnmpCheck(SnmpCheck):
  def __init__(self):
    self.name = 'cpu'
    self.oid = '1.3.6.1.2.1.25.3.3.1.2.1'

  def get(self, host, w, c, password):
    values = []
    for i in range(5):
      values.append(int(super(CpuSnmpCheck, self).get_value(host, self.oid, password)[0].split()[-1]))
      time.sleep(1)

    value = int(sum(values) / len(values))
    status = super(CpuSnmpCheck, self).get_status(value, w, c)

    return super(CpuSnmpCheck, self).build_result(status, 'Load = %u%%', value)

class RamSnmpCheck(SnmpCheck):
  def __init__(self):
    self.name = 'ram'
    self.used_oid = '1.3.6.1.2.1.25.2.3.1.6.65536'
    self.total_oid = '1.3.6.1.2.1.25.2.3.1.5.65536'

  def get(self, host, w, c, password):
    used = int(super(RamSnmpCheck, self).get_value(host, self.used_oid, password)[0].split()[-1])
    total = int(super(RamSnmpCheck, self).get_value(host, self.total_oid, password)[0].split()[-1])
    value = int(round(100.0 * used / total))

    status = super(RamSnmpCheck, self).get_status(value, w, c)

    return super(RamSnmpCheck, self).build_result(status, 'Used memory = %u%%', value)

class TemperatureSnmpCheck(SnmpCheck):
  def __init__(self):
    self.name = 'temp'
    self.oid = '1.3.6.1.4.1.14988.1.1.3.10.0'

  def get(self, host, w, c, password):
    value = int(super(TemperatureSnmpCheck, self).get_value(host, self.oid, password)[0].split()[-1]) / 10

    status = super(TemperatureSnmpCheck, self).get_status(value, w, c)

    return super(TemperatureSnmpCheck, self).build_result(status, 'Temperature = %u C', value)

class CpuTemperatureSnmpCheck(TemperatureSnmpCheck):
  def __init__(self):
    self.name = 'cpu-temp'
    self.oid = '1.3.6.1.4.1.14988.1.1.3.11.0'

parser = OptionParser()
parser.add_option("-t", "--type", dest="type", help="snmp command type")
parser.add_option("-H", "--host", dest="host", help="host address")
parser.add_option("-w", type="int", dest="wrta", help="warning at")
parser.add_option("-c", type="int", dest="crta", help="critical at")
parser.add_option("-p", "--password", dest="password", help="SNMP v3 password")
(options, args) = parser.parse_args()

if not options.host or not options.wrta or not options.crta or not options.type or not options.password:
  print('Wrong arguments passed')
  exit(1)

checks = [CpuSnmpCheck(), TemperatureSnmpCheck(), CpuTemperatureSnmpCheck(), RamSnmpCheck()]

for check in checks:
  if check.name == options.type:
    result = check.get(options.host, options.wrta, options.crta, options.password)
    print(result[1])
    exit(result[0])
