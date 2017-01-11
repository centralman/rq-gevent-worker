import gevent.monkey

gevent.monkey.patch_all()

import socket
import logging
import json
from io import BytesIO
from functools import partial
from collections import defaultdict

import kafka

from utils import tarlib, event_loop
from utils.log import setup_logging
from core.ffan.helpers import fetch_ffan_macs
from core import resolver
from core import protocol
from core import zhongke
from core import ffan
from conf import config

setup_logging()

log = logging.getLogger(__name__)

MAX_FETCH_SIZE = 64 * 1024 * 1024


def fetch_sniffer(consumer, sniffer_map, sniffer_map_zk, sniffer_map_ff):
    offset_messages = consumer.get_messages(count=300, timeout=0.2)

    for om in offset_messages:
        try:
            device_mac, file_name, data = om.message.value.split('+', 2)
        except ValueError:
            continue

        if device_mac in config.MACS:
            try:
                archive = tarlib.extract_to_memory(file_obj=BytesIO(data))
            except tarlib.Error:
                log.warn('Fail to extract file %s', file_name)
                continue

            data_map = resolver.resolve(device_mac, archive)
            if not data_map:
                continue
            for data_type, seq in data_map.iteritems():
                sniffer_map[data_type] += '\n'.join('\t'.join(x) for x in seq) + '\n'

        if device_mac in config.ZHONGKE_MACS:
            try:
                archive = tarlib.extract_to_memory(file_obj=BytesIO(data))
            except tarlib.Error:
                log.warn('Fail to extract file %s', file_name)
                continue

            data_list = zhongke.resolver.resolve(device_mac, archive)
            if not data_list:
                continue

            sniffer_map_zk["snza"] += "\n".join(
                [json.dumps({"data": msg, "packType": 1}) for msg in data_list]) + "\n"

        if device_mac in config.GTBH_MACS:
            try:
                archive = tarlib.extract_to_memory(file_obj=BytesIO(data))
            except tarlib.Error:
                log.warn('Fail to extract file %s', file_name)
                continue

            data_list = zhongke.resolver.resolve(device_mac, archive, 113617)
            if not data_list:
                continue

            sniffer_map_zk["gtbh"] += "\n".join(
                [json.dumps({"data": msg, "packType": 1}) for msg in data_list]) + "\n"

        if device_mac in config.BJFK_MACS:
            try:
                archive = tarlib.extract_to_memory(file_obj=BytesIO(data))
            except tarlib.Error:
                log.warn('Fail to extract file %s', file_name)
                continue

            data_list = zhongke.resolver.resolve(device_mac, archive, 120746)
            if not data_list:
                continue

            sniffer_map_zk["bjfk"] += "\n".join(
                [json.dumps({"data": msg, "packType": 1}) for msg in data_list]) + "\n"

        if device_mac in fetch_ffan_macs():
            try:
                archive = tarlib.extract_to_memory(file_obj=BytesIO(data))
            except tarlib.Error:
                log.warn('Fail to extract file %s', file_name)
                continue

            data_map = ffan.resolver.resolve(device_mac, archive)
            if not data_map:
                continue
            for data_type, data_list in data_map.iteritems():
                sniffer_map_ff[data_type].extend(data_list)


def commit_sniffer(sniffer_map):
    if not sniffer_map:
        return
    file_name, content = protocol.pack(sniffer_map)
    try:
        protocol.send_file(file_name, content,
                           **config.XDES['FTP'])
    except KeyError as ex:
        log.warn('No configuration for %s - %s', 'FTP', ex.message)
    except socket.error as ex:
        log.warn('Fail to send file - %s', ex)
    finally:
        sniffer_map.clear()


def commit_sniffer_zk(sniffer_map_zk):
    try:
        zhongke.protocol.send(sniffer_map_zk)
    finally:
        sniffer_map_zk.clear()


def commit_sniffer_ff(sniffer_map_ff):
    try:
        ffan.protocol.pack(sniffer_map_ff)
    finally:
        sniffer_map_ff.clear()


def cycle():
    client = kafka.KafkaClient(hosts=config.KAFKA_HOSTS)
    consumer = kafka.SimpleConsumer(client,
                                    group=config.KAFKA_GROUP,
                                    topic=config.KAFKA_TOPIC,
                                    fetch_size_bytes=64 * 1024,
                                    buffer_size=256 * 1024,
                                    max_buffer_size=MAX_FETCH_SIZE)

    loop = event_loop.Loop()
    sniffer_map = defaultdict(str)
    sniffer_map_zk = defaultdict(str)
    sniffer_map_ff = defaultdict(list)

    loop.add_callback(partial(fetch_sniffer, consumer, sniffer_map, sniffer_map_zk, sniffer_map_ff))
    # Commit every 5 seconds
    event_loop.PeriodicCallback(
        partial(commit_sniffer, sniffer_map), 5 * 1000, loop=loop
    ).start()

    event_loop.PeriodicCallback(
        partial(commit_sniffer_zk, sniffer_map_zk), 5 * 1000, loop=loop
    ).start()

    event_loop.PeriodicCallback(
        partial(commit_sniffer_ff, sniffer_map_ff), 30 * 1000, loop=loop
    ).start()

    log.warn('start main loop...')
    loop.start()


if __name__ == '__main__':
    cycle()
