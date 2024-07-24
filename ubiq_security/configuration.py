#!/usr/bin/env python3

import os
import json
from enum import Enum

class TimestampGranularity(Enum):
    MICROS = 1
    MILLIS = 2
    SECONDS = 3
    MINUTES = 4
    HOURS = 5
    HALF_DAYS = 6
    DAYS = 7

def get_timestamp_granularity(value):
    s = value.upper()
    ret = TimestampGranularity.MICROS
    if s == "MILLIS":
        ret = TimestampGranularity.MILLIS
    elif s == "SECONDS":
        ret = TimestampGranularity.SECONDS
    elif s == "MINUTES":
        ret = TimestampGranularity.MINUTES
    elif s == "HOURS":
        ret = TimestampGranularity.HOURS
    elif s == "HALF_DAYS":
        ret = TimestampGranularity.HALF_DAYS
    elif s == "DAYS":
        ret = TimestampGranularity.DAYS
    else:
        ret = TimestampGranularity.MICROS
    
    return ret

class configInfo:

    def __init__(self, event_reporting_wake_interval, event_reporting_minimum_count, event_reporting_flush_interval, event_reporting_trap_exceptions, event_reporting_timestamp_granularity, event_reporting_synchronous, logging_verbose, key_caching_unstructured, key_caching_encrypt):
        self.__event_reporting_wake_interval = event_reporting_wake_interval
        self.__event_reporting_minimum_count = event_reporting_minimum_count
        self.__event_reporting_flush_interval = event_reporting_flush_interval
        self.__event_reporting_trap_exceptions = event_reporting_trap_exceptions
        self.__event_reporting_timestamp_granularity = event_reporting_timestamp_granularity
        self.__event_reporting_synchronous = event_reporting_synchronous
        self.__logging_verbose = logging_verbose
        self.__key_caching_unstructured = key_caching_unstructured
        self.__key_caching_encrypt = key_caching_encrypt

    def get_event_reporting_wake_interval(self):
        return self.__event_reporting_wake_interval
    event_reporting_wake_interval=property(get_event_reporting_wake_interval)

    def get_event_reporting_minimum_count(self):
        return self.__event_reporting_minimum_count
    event_reporting_minimum_count=property(get_event_reporting_minimum_count)

    def get_event_reporting_flush_interval(self):
        return self.__event_reporting_flush_interval
    event_reporting_flush_interval = property(get_event_reporting_flush_interval)

    def get_event_reporting_trap_exceptions(self):
        return self.__event_reporting_trap_exceptions
    event_reporting_trap_exceptions = property(get_event_reporting_trap_exceptions)
    
    def get_event_reporting_timestamp_granularity(self):
        return self.__event_reporting_timestamp_granularity
    event_reporting_timestamp_granularity = property(get_event_reporting_timestamp_granularity)

    def get_event_reporting_synchronous(self):
        return self.__event_reporting_synchronous
    event_reporting_synchronous = property(get_event_reporting_synchronous)
    
    def get_logging_verbose(self):
        return self.__logging_verbose
    logging_verbose = property(get_logging_verbose)

    def get_key_caching_unstructured(self):
        return self.__key_caching_unstructured
    key_caching_unstructured = property(get_key_caching_unstructured)
    
    def get_key_caching_encrypt(self):
        return self.__key_caching_encrypt
    key_caching_encrypt = property(get_key_caching_encrypt)

    def set(self):
        return (self.__event_reporting_wake_interval != None 
                and self.__event_reporting_minimum_count != None 
                and self.__event_reporting_flush_interval != None
                and self.__logging_verbose != None)

class ubiqConfiguration(configInfo):

    def load_config_file(self, config_file):
        try:
            with open(config_file) as json_file:
                config = json.load(json_file)
                self.set_defaults()
                if 'event_reporting' in config:
                    if 'wake_interval' in config['event_reporting']:
                        self.__event_reporting_wake_interval = config['event_reporting']['wake_interval']
                    if 'minimum_count' in config['event_reporting']:
                        self.__event_reporting_minimum_count = config['event_reporting']['minimum_count']
                    if 'flush_interval' in config['event_reporting']:
                        self.__event_reporting_flush_interval = config['event_reporting']['flush_interval']
                    if 'trap_exceptions' in config['event_reporting']:
                        self.__event_reporting_trap_exceptions = config['event_reporting']['trap_exceptions']
                    if 'timestamp_granularity' in config['event_reporting']:
                        self.__event_reporting_timestamp_granularity = get_timestamp_granularity(config['event_reporting']['timestamp_granularity'])
                    if 'synchronous' in config['event_reporting']:
                        self.__event_reporting_synchronous = config['event_reporting']['synchronous']
                if 'logging' in config:
                    if 'verbose' in config['logging']:
                        self.__logging_verbose = config['logging']['verbose']
                if 'key_caching' in config:
                    if 'unstructured' in config['key_caching']:
                        self.__key_caching_unstructured = config['key_caching']['unstructured']
                    if 'encrypt' in config['key_caching']:
                        self.__key_caching_encrypt = config['key_caching']['encrypt']
        except FileNotFoundError:
            # If file doesn't exist, use defaults
            self.set_defaults()

    def set_defaults(self):
        self.__event_reporting_wake_interval = 10
        self.__event_reporting_minimum_count = 50
        self.__event_reporting_flush_interval = 90
        self.__event_reporting_trap_exceptions = False
        self.__event_reporting_timestamp_granularity = TimestampGranularity.MICROS
        self.__event_reporting_synchronous = False
        self.__logging_verbose = False
        self.__key_caching_unstructured = True
        self.__key_caching_encrypt = False

    def __init__(self, config_file = None):

        self.__event_reporting_wake_interval = None
        self.__event_reporting_minimum_count = None
        self.__event_reporting_flush_interval = None
        self.__event_reporting_trap_exceptions = None
        self.__event_reporting_timestamp_granularity = None
        self.__event_reporting_synchronous = None
        self.__logging_verbose = None
        self.__key_caching_unstructured = None
        self.__key_caching_encrypt = None

        if (config_file == None):
            from os.path import expanduser
            home = expanduser("~")
            config_file = os.path.join(home, ".ubiq", "configuration")

        if os.path.exists(config_file):
            self.load_config_file(config_file)
        else:
            self.set_defaults()

        configInfo.__init__(self, self.__event_reporting_wake_interval , self.__event_reporting_minimum_count, self.__event_reporting_flush_interval, self.__event_reporting_trap_exceptions, self.__event_reporting_timestamp_granularity, self.__event_reporting_synchronous, self.__logging_verbose, self.__key_caching_unstructured, self.__key_caching_encrypt)
