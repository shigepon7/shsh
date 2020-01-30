#!/usr/local/bin/python3

# Copyright 2020 Daisuke SHIGETA <a.k.a. @shigepon7>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions: The above copyright
# notice and this permission notice shall be included in all copies or
# substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS",
# WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from functools import reduce

import argparse
import asyncio
import datetime
import logging
import mysql.connector
import queue
import requests
import socket
import struct
import sys
import traceback


class Logger(object):

    def __init__(self, slack, level=logging.INFO):
        self.slack = slack
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(level)
        self.ch = logging.StreamHandler()
        self.ch.setLevel(level)
        self.fm = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        self.ch.setFormatter(self.fm)
        self.logger.addHandler(self.ch)

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)
        self.slack.post_manage(msg)

    def error(self, msg):
        self.logger.error(msg)
        self.slack.post_manage(msg)

    def critical(self, msg):
        self.logger.critical(msg)
        self.slack.post_manage(msg)


class Slack(object):

    def __init__(self, token, channel, mchannel):
        self.token = token
        self.channel = channel
        self.mchannel = mchannel

    def post(self, message):
        data = {}
        data['token'] = self.token
        data['channel'] = self.channel
        data['as_user'] = True
        data['text'] = message
        requests.post('https://slack.com/api/chat.postMessage', data=data)

    def post_manage(self, message):
        data = {}
        data['token'] = self.token
        data['channel'] = self.mchannel
        data['as_user'] = True
        data['text'] = message
        requests.post('https://slack.com/api/chat.postMessage', data=data)


class CommandProtocol(asyncio.Protocol):

    def __init__(self, callback, logger):
        self.callback = callback
        self.logger = logger

    def connection_made(self, transport):
        self.logger.debug('command connection_made')
        self.transport = transport

    def data_received(self, data):
        self.logger.debug('command data_received %'.format(data.decode()))
        try:
            msg = self.callback(data.decode())
            if len(msg) < 1:
                msg = '.'
            self.transport.write(msg.encode())
        except Exception as e:
            self.logger.error(traceback.format_exc())


class EchonetLiteProtocol(asyncio.DatagramProtocol):

    PORT = 3610
    MULTI = '224.0.23.0'
    MULTI6 = 'ff02::1'

    SETI_SNA = '50'
    SETC_SNA = '51'
    GET_SNA = '52'
    INF_SNA = '53'
    SETGET_SNA = '5e'
    SETI = '60'
    SETC = '61'
    GET = '62'
    INF_REQ = '63'
    SETGET = '6e'
    SET_RES = '71'
    GET_RES = '72'
    INF = '73'
    INFC = '74'
    INFC_RES = '7a'
    SETGET_RES = '7e'
    ESV = {
        '50': 'SETI_SNA',
        '51': 'SETC_SNA',
        '52': 'GET_SNA',
        '53': 'INF_SNA',
        '5e': 'SETGET_SNA',
        '60': 'SETI',
        '61': 'SETC',
        '62': 'GET',
        '63': 'INF_REQ',
        '6e': 'SETGET',
        '71': 'SET_RES',
        '72': 'GET_RES',
        '73': 'INF',
        '74': 'INFC',
        '7a': 'INFC_RES',
        '7e': 'SETGET_RES'
    }

    def __init__(self, logger, objList=['05ff01'], isIPv6=False, userfunc=None):
        self.isIPv6 = isIPv6
        self.cls = []
        self.node = {
            '80': [0x30],
            '82': [0x01, 0x0a, 0x01, 0x00],
            '83': [0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00],
            '8a': [0x00, 0x00, 0x77],
            '9d': [0x02, 0x80, 0xd5],
            '9e': [0x00],
            '9f': [0x09, 0x80, 0x82, 0x83, 0x8a, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7],
            'd3': [0x00, 0x00, 0x01],
            'd4': [0x00, 0x02],
            'd5': [],
            'd6': [],
            'd7': []
        }
        self.facilities = {}
        self.obj = [bytes.fromhex(o) for o in objList]
        self.cls = list(set([o[:2] for o in self.obj]))
        self.node['d3'] = [0x00, 0x00, len(self.obj)]
        self.node['d5'] = [len(self.obj)]
        for o in self.obj:
            self.node['d5'].extend(o)
        self.node['d6'] = self.node['d5']
        self.node['d4'] = [0x00, len(self.cls) + 1]
        self.node['d7'] = [len(self.cls)]
        for c in self.cls:
            self.node['d7'].extend(c)
        self.tid = 0
        self.transport = None
        self.userfunc = userfunc
        self.logger = logger
        self.logger.info('initialized.')

    def connection_made(self, transport):
        self.logger.info('connection made.')
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'eth0')
        if self.isIPv6:
            mreq = struct.pack("4sl", socket.inet_aton(self.MULTI6), socket.INADDR_ANY)
        else:
            mreq = struct.pack("4sl", socket.inet_aton(self.MULTI), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        if self.transport is None:
            self.transport = transport
            self.send('0ef001', '0ef001', self.INF, {'d5': bytes(self.node['d5']).hex()})

    def connection_lost(self, exc):
        self.logger.info('connection lost.')

    def datagram_received(self, data, addr):
        els = self.parse(data)
        time = datetime.datetime.now().strftime('%H:%M:%S')
        self.logger.debug('R {} {} {} {} {} {} {} {}'.format(addr[0], time, els['tid'], els['seoj'], els['deoj'], self.ESV[els['esv']], els['opc'], els['details']))
        if els is None:
            return
        if els['ehd'] != '1081':
            return
        if els['deoj'] == '0ef000' or els['deoj'] == '0ef001':
            if els['esv'] == self.SETI_SNA or els['esv'] == self.SETC_SNA or els['esv'] == self.GET_SNA \
               or els['esv'] == self.INF_SNA or els['esv'] == self.SETGET_SNA:
                pass
            if els['esv'] == self.GET:
                for d in els['details']:
                    if d in self.node:
                        self.send('0ef001', els['seoj'], self.GET_RES, {d: bytes(self.node[d]).hex()},
                                  tid=els['tid'], ip=addr[0])
                    else:
                        self.send('0ef001', els['seoj'], self.GET_SNA, {}, tid=els['tid'], ip=addr[0])
            elif els['esv'] == self.INF_REQ:
                if 'd5' in els['details'] and els['details']['d5'] == '':
                    self.send('0ef001', els['seoj'], self.INF, {'d5': self.node['d5']})
            elif els['esv'] == self.SET_RES:
                if els['detail'][0:2] == '00':
                    self.send('05ff01', els['seoj'], self.GET, {'00': ''}, ip=addr[0])
            elif els['esv'] == self.GET_RES:
                if els['seoj'][0:4] == '0ef0' and 'd6' in els['details'] and len(els['details']['d6']) > 0:
                    data = bytes.fromhex(els['details']['d6'])
                    for instNum in range(data[0], 0, -1):
                        self.getPropertyMaps(addr[0], data[(instNum - 1) * 3 + 1:(instNum - 1) * 3 + 4].hex())
                elif '9f' in els['details'] and len(els['details']['9f']) > 0:
                    data = bytes.fromhex(els['details']['9f'])
                    if len(data) < 17:
                        for i in range(data[0]):
                            if data[i + 1] != 0x9f:
                                self.send('0ef001', els['seoj'], self.GET,
                                          {bytes(data[i + 1:i + 2]).hex(): ''}, ip=addr[0])
                    else:
                        data = self.parseMapForm2(data)
                        for i in range(data[0]):
                            if data[i + 1] != 0x9f:
                                self.send('0ef001', els['seoj'], self.GET,
                                          {bytes(data[i + 1:i + 2]).hex(): ''}, ip=addr[0])
            elif els['esv'] == self.INF:
                if els['seoj'][0:4] == '0ef0' and 'd5' in els['details'] and len(els['details']['d5']) > 0:
                    data = bytes.fromhex(els['details']['d5'])
                    for instNum in range(data[0], 0, -1):
                        self.getPropertyMaps(addr[0], data[(instNum - 1) * 3 + 1:(instNum - 1) * 3 + 4].hex())
            elif els['esv'] == self.INFC:
                if 'd5' in els['details'] and len(els['details']['d5']) > 0:
                    self.getPropertyMaps(addr[0], '0ef000')
                    data = bytes.fromhex(els['details']['d5'])
                    for instNum in range(data[0], 0, -1):
                        self.getPropertyMaps(addr[0], data[(instNum - 1) * 3 + 1:(instNum - 1) * 3 + 4].hex())
        if els['esv'] != self.GET and els['esv'] != self.INF_REQ:
            self.renewFacilities(addr[0], els)
        if self.userfunc is not None:
            self.userfunc(addr[0], els)

    def error_received(self, err):
        self.logger.warning('error received {}'.format(err))

    def send(self, seoj, deoj, esv, data,
             tid=None, ip=None, port=None, addr=None):
        if ip is None:
            if self.isIPv6:
                ip = self.MULTI6
            else:
                ip = self.MULTI
        if port is None:
            port = self.PORT
        if addr is None:
            addr = (ip, port)
        packet = [0x10, 0x81]
        if tid is None:
            self.tid += 1
            if self.tid > 65535:
                self.tid = 1
            tid = struct.pack('!H', self.tid)
        else:
            tid = bytes.fromhex(tid)
        packet.extend(tid)
        packet.extend(bytes.fromhex(seoj))
        packet.extend(bytes.fromhex(deoj))
        packet.extend(bytes.fromhex(esv))
        packet.append(len(data))
        for d in data:
            epc = bytes.fromhex(d)
            packet.extend(epc)
            if len(data[d]) == 0:
                packet.append(0)
            else:
                edt = bytes.fromhex(data[d])
                packet.append(len(edt))
                packet.extend(edt)
        els = self.parse(packet)
        time = datetime.datetime.now().strftime('%H:%M:%S')
        self.logger.debug('S {} {} {} {} {} {} {} {}'.format(addr[0], time, els['tid'], els['seoj'], els['deoj'], self.ESV[els['esv']], els['opc'], els['details']))
        self.transport.sendto(bytes(packet), addr)

    def parse(self, packet):
        ret = {}
        if len(packet) < 14:
            self.logger.error('parse() error. packet is less than 14 bytes.\npacket is "{}"'.format(packet.hex()))
            return None
        ret['ehd'] = bytes(packet[0:2]).hex()
        ret['tid'] = bytes(packet[2:4]).hex()
        ret['seoj'] = bytes(packet[4:7]).hex()
        ret['deoj'] = bytes(packet[7:10]).hex()
        ret['edata'] = bytes(packet[10:]).hex()
        ret['esv'] = bytes(packet[10:11]).hex()
        ret['opc'] = bytes(packet[11:12]).hex()
        ret['detail'] = bytes(packet[12:]).hex()
        ret['details'] = {}
        idx = 12
        for p in range(packet[11]):
            epc = bytes(packet[idx:idx + 1]).hex()
            pdc = packet[idx + 1]
            edt = bytes(packet[idx + 2:idx + 2 + pdc]).hex()
            ret['details'][epc] = edt
            idx += 2 + pdc
        return ret

    def renewFacilities(self, ip, els):
        if ip not in self.facilities:
            self.facilities[ip] = {}
        if els['seoj'] not in self.facilities[ip]:
            self.facilities[ip][els['seoj']] = {}
            self.getPropertyMaps(ip, els['seoj'])
        for epc in els['details']:
            if epc not in self.facilities[ip][els['seoj']]:
                self.facilities[ip][els['seoj']][epc] = {}
            self.facilities[ip][els['seoj']][epc] = els['details'][epc]

    def search(self):
        self.send('0ef001', '0ef000', self.GET, {'d6': ''})

    def getPropertyMaps(self, ip, eoj):
        # self.send('0ef001', eoj, self.GET, {'9d': ''}, ip=ip)
        # self.send('0ef001', eoj, self.GET, {'9e': ''}, ip=ip)
        self.send('0ef001', eoj, self.GET, {'9f': ''}, ip=ip)
        pass

    def parseMapForm2(self, data):
        ret = []
        val = 0x80
        for bit in range(8):
            for byt in range(1, 17):
                if (data[byt] >> bit) & 0x01 != 0x00:
                    ret.append(val)
                val += 1
        ret.insert(0, len(ret))
        return ret


class EchonetLiteClass(object):

    def __init__(self, logger, sh, elp, ip):
        self.logger = logger
        self.sh = sh
        self.elp = elp
        self.ip = ip
        self.name = None
        self.ctl = '05ff01'
        self.eoj = None
        self.interval = 60
        self.get = []
        self.gidx = -1
        self.set = []
        self.db = {}
        self.ptime = 0
        self.table = None
        self.dt = None
        self.pvalues = {}

    def send(self):
        param = dict(zip(self.get[self.gidx], [''] * len(self.get[self.gidx])))
        self.elp.send(self.ctl, self.eoj, self.elp.GET, param, ip=self.ip)

    def period(self, ils, ltime):
        if self.eoj in ils:
            ptime = int(ltime / self.interval)
            if self.ptime != ptime:
                self.gidx = 0
                self.dt = datetime.datetime.now().replace(second=0, microsecond=0)
                self.send()
                self.ptime = ptime
        return []

    def callback(self, els, ip):
        values = {}
        if self.table is not None and self.dt is not None:
            sql = 'select * from {} where dt = "{}";'.format(self.table, self.dt)
            try:
                values = self.sh.dbfetch(sql)
            except:
                sys.exit('DB Fetch Error')
        if self.eoj is None:
            self.eoj = els['seoj']
        for key in reduce(lambda a,b:a+b, self.get):
            if key in els['details'] and key != '8c':
                values.update(dict(self.decode(key, els['details'][key])))
        if self.name is None and '8c' in els['details']:
            d = els['details']['8c']
            self.model = ''.join([chr(int(''.join(i), 16)) for i in zip(*[iter(d)]*2) if ''.join(i) != '00'])
            self.name = self.identify(els, ip, self.model)
            if self.name is not None:
                self.createtable()
                self.logger.warning('{} : {} -> {}'.format(self.__class__.__name__, self.model, self.name))
        if self.name is not None and len(values) > 0:
            if 'dt' not in values:
                values['dt'] = self.dt
            for k, v in list(values.items()):
                if v is None:
                    values.pop(k)
            for k in values:
                if k not in self.pvalues:
                    continue
                if k == 'dt':
                    continue
                if self.pvalues[k] != values[k]:
                    self.logger.info('{} : {} : {} : {} -> {}'.format(values['dt'], self.name, k, self.pvalues[k], values[k]))
                    self.changed(k, self.pvalues[k], values[k])
            columns = ', '.join(values.keys())
            row = ', '.join(['"{}"'.format(v) for v in values.values()])
            update = ', '.join(['{} = "{}"'.format(k, v) for k, v in values.items()])
            sql = 'insert into {} ({}) values ({}) on duplicate key update {};'.format(self.table, columns, row, update)
            self.sh.dbcommit(sql)
        if self.gidx >= 0:
            self.gidx += 1
            if len(self.get) > self.gidx:
                self.send()
                return
        self.pvalues = values

    def identify(self, els, ip, model):
        return None

    def decode(self, key, value):
        return [[key, value]]

    def createtable(self):
        if len(self.db) == 0:
            return
        self.table = '{}'.format(self.name)
        sql = 'create table if not exists {} (dt datetime primary key, '.format(self.table)
        for d in self.db:
            sql += '{} {}, '.format(d, self.db[d])
        sql = sql[:-2] + ');'
        self.sh.dbexec(sql)

    def commandmessage(self, msg):
        ret = self.command(msg)
        if len(self.set) == 0:
            return ret
        if self.name is not None and self.name not in msg:
            return ret
        body = msg.replace(self.name, '')
        for p in self.set:
            if p[0] in body:
                for k, v in p[2].items():
                    if k in body:
                        self.elp.send(self.ctl, self.eoj, self.elp.SETI, {p[1]: v}, ip=self.ip)
                        ret += ['{}の{}を{}したよ'.format(self.name, p[0], k)]
        return ret

    def changed(self, key, pvalue, value):
        pass

    def command(self, msg):
        return []


class SmartHome(object):

    def __init__(self, slack, logger, dbhost, dbuser, dbpw, dbname, isIPv6=False):
        self.slack = slack
        self.logger = logger
        self.isIPv6 = isIPv6
        self.interval = 1
        if isIPv6:
            addr = ('::', EchonetLiteProtocol.PORT)
        else:
            addr = ('0.0.0.0', EchonetLiteProtocol.PORT)
        self.conn = mysql.connector.connect(host=dbhost, user=dbuser, password=dbpw, database=dbname)
        self.cur = self.conn.cursor()
        self.need_commit = False
        self.loop = asyncio.get_event_loop()
        self.protocol = None
        self.connect = self.loop.create_datagram_endpoint(lambda: EchonetLiteProtocol(logger=self.logger,
                                                                                      objList=['05ff01'],
                                                                                      isIPv6=self.isIPv6,
                                                                                      userfunc=self.callback),
                                                          local_addr=addr)
        self.transport, self.protocol = self.loop.run_until_complete(self.connect)
        self.clazz = {}
        self.devices = {}
        self.server = self.loop.run_until_complete(self.loop.create_server(lambda: CommandProtocol(self.commandmessage, self.logger), '0.0.0.0', 51964))
        self.event_queue = queue.Queue()
        self.protocol.search()

    def __del__(self):
        self.cur.close()
        self.conn.close()
        self.controller.stop()
        self.transport.close()
        self.server.close()
        self.loop.close()

    def mainloop(self):
        self.logger.debug('start mainloop')
        now = self.loop.time()
        self.nxt = (int(now / self.interval) + 1) * self.interval
        self.loop.call_at(self.nxt, self.period)
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            pass

    def period(self):
        self.logger.debug('start period')
        self.nxt += self.interval
        self.loop.call_at(self.nxt, self.period)
        try:
            ils = {}
            for ip in self.protocol.facilities:
                if '0ef001' in self.protocol.facilities[ip] and 'd5' in self.protocol.facilities[ip]['0ef001']:
                    ilist = bytes.fromhex(self.protocol.facilities[ip]['0ef001']['d5'])
                    for i in range(ilist[0]):
                        clazz = ilist[i * 3 + 1:i * 3 + 4].hex()
                        if clazz in ils:
                            ils[clazz].append(ip)
                        else:
                            ils[clazz] = [ip]
                if '0ef001' in self.protocol.facilities[ip] and 'd6' in self.protocol.facilities[ip]['0ef001']:
                    ilist = bytes.fromhex(self.protocol.facilities[ip]['0ef001']['d6'])
                    for i in range(ilist[0]):
                        clazz = ilist[i * 3 + 1:i * 3 + 4].hex()
                        if clazz in ils:
                            ils[clazz].append(ip)
                        else:
                            ils[clazz] = [ip]
        except Exception as e:
            self.logger.error(traceback.format_exc())
        ltime = int(self.loop.time())
        if ltime % 3600 == 0:
            self.protocol.search()
        for clip in self.devices:
            self.logger.debug('start period {}'.format(self.devices[clip].name))
            try:
                self.devices[clip].period(ils, ltime)
            except Exception as e:
                self.logger.error(traceback.format_exc())
        self.logger.debug('start period event_handler')
        try:
            self.event_handler()
        except Exception as e:
            self.logger.error(traceback.format_exc())
        if self.need_commit:
            self.logger.debug('start period commit')
            self.need_commit = False
            try:
                if self.conn.is_connected():
                    self.conn.commit()
                else:
                    self.conn.ping(reconnect=True)
                    self.cur = self.conn.cursor()
            except Exception as e:
                self.logger.error(traceback.format_exc())

    def callback(self, ip, els):
        try:
            if self.protocol is None:
                return
            if els['esv'] != self.protocol.GET_RES:
                if els['seoj'] != '013001':
                    self.logger.debug('{} {}'.format(ip, els))
            clip = '{}_{}'.format(els['seoj'], ip)
            if clip not in self.devices:
                g = globals()
                cl = els['seoj'][:4]
                if cl in self.clazz and self.clazz[cl] in g:
                    self.logger.info('****** found {}'.format(cl))
                    self.devices[clip] = g[self.clazz[cl]](self, self.protocol, ip)
            if clip in self.devices:
                self.devices[clip].callback(els, ip)
        except Exception as e:
            self.logger.error(traceback.format_exc())

    def commandmessage(self, msg):
        ret = []
        msglen = 0
        whole_replace = {}
        word_replace = {}
        self.logger.info('app input - {}'.format(msg))
        if msg in whole_replace:
            msg = whole_replace[msg]
        for k, v in word_replace.items():
            msg = msg.replace(k, v)
        for clip in self.devices:
            try:
                ret += self.devices[clip].commandmessage(msg)
            except Exception as e:
                self.logger.error(traceback.format_exc())
        self.logger.debug('EchonetLiteClass msg process done')
        if msglen != len(ret):
            self.logger.info('EchonetLiteClass responsed')
            msglen = len(ret)
        if msg == 'サーチ':
            self.protocol.search()
            ret += ['サーチ開始']
        if msg == '機器リスト':
            for clip in self.devices:
                ret += ['{} : {}'.format(self.devices[clip].name, clip)]
        if msg == 'プロパティマップ':
            for ip in self.protocol.facilities:
                for seoj in self.protocol.facilities[ip]:
                    if '9d' in self.protocol.facilities[ip][seoj]:
                        ret += ['{} : {} : 9d : {}'.format(ip, seoj, self.protocol.facilities[ip][seoj]['9d'])]
                    if '9e' in self.protocol.facilities[ip][seoj]:
                        ret += ['{} : {} : 9e : {}'.format(ip, seoj, self.protocol.facilities[ip][seoj]['9e'])]
                    if '9f' in self.protocol.facilities[ip][seoj]:
                        ret += ['{} : {} : 9f : {}'.format(ip, seoj, self.protocol.facilities[ip][seoj]['9f'])]
        if msg == '名前登録':
            classes = {}
            for clip in self.devices:
                cls = clip[:4]
                if cls not in classes:
                    classes[cls] = [self.devices[clip]]
                else:
                    classes[cls].append(self.devices[clip])
            for cls, devices in classes.items():
                if len(devices) < 2:
                    continue
                for idx, device in enumerate(devices):
                    if device.name is not None:
                        device.name = '{}{}'.format(re.sub(r'([^\d]+)\d+', r'\1', device.name), idx+1)
            ret += ['名前登録が完了したよ']
        self.logger.debug('Other commands msg process done')
        if msglen != len(ret):
            self.logger.info('Other commands responsed')
            msglen = len(ret)
        if len(ret) == 0:
            self.logger.info('No response')
        return '\n'.join(ret)

    def dbexec(self, sql):
        if self.conn.is_connected():
            self.cur.execute(sql)

    def dbfetch(self, sql):
        if not self.conn.is_connected():
            return {}
        self.cur.execute(sql)
        columns = self.cur.column_names
        values = self.cur.fetchall()
        if len(values) > 0:
            ret = dict(zip(columns, values[0]))
        else:
            ret = {}
        return ret

    def dbfetchm(self, sql):
        if not self.conn.is_connected():
            return []
        self.cur.execute(sql)
        columns = self.cur.column_names
        values = self.cur.fetchall()
        return [dict(zip(columns, v)) for v in values] 

    def dbcommit(self, sql):
        if self.conn.is_connected():
            self.cur.execute(sql)
        self.need_commit = True

    def event_push(self, name, value=0):
        self.logger.info('new event "{}" value "{}"'.format(name, value))
        self.event_queue.put((name, value))

    def event_handler(self):
        while not self.event_queue.empty():
            event = self.event_queue.get()
            handler = getattr(self, event[0], None)
            if handler is None:
                continue
            handler(event[1])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SHSH(SHigepon SmartHome) controler', add_help=False)
    parser.add_argument('-t', '--token', help='slack token.')
    parser.add_argument('-c', '--channel', help='slack channel.')
    parser.add_argument('-m', '--mchannel', help='slack channel for management.')
    parser.add_argument('-h', '--dbhost', help='database host name.')
    parser.add_argument('-u', '--dbuser', help='database username.')
    parser.add_argument('-p', '--dbpw', help='database password.')
    parser.add_argument('-d', '--dbname', help='database name.')
    errmsg = []
    args = parser.parse_args()
    if args.token is None:
        errmsg.append('need token parameter')
    if args.channel is None:
        errmsg.append('need channel parameter')
    if args.mchannel is None:
        errmsg.append('need mchannel parameter')
    if args.dbhost is None:
        errmsg.append('need dbhost parameter')
    if args.dbuser is None:
        errmsg.append('need dbuser parameter')
    if args.dbpw is None:
        errmsg.append('need dbpw parameter')
    if args.dbname is None:
        errmsg.append('need dbname parameter')
    if len(errmsg) > 0:
        sys.exit('\n'.join(errmsg))
    slack = Slack(args.token, args.channel, args.mchannel)
    logger = Logger(slack, logging.DEBUG)
    sh = SmartHome(slack, logger, args.dbhost, args.dbuser, args.dbpw, args.dbname)
    sh.mainloop()
