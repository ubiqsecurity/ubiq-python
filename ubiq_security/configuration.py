#!/usr/bin/env python3

import os
import json

class configInfo:

    def __init__(self, event_reporting_wake_interval, event_reporting_minimum_count, event_reporting_flush_interval, event_reporting_trap_exceptions, logging_verbose):
        self.__event_reporting_wake_interval = event_reporting_wake_interval
        self.__event_reporting_minimum_count = event_reporting_minimum_count
        self.__event_reporting_flush_interval = event_reporting_flush_interval
        self.__event_reporting_trap_exceptions = event_reporting_trap_exceptions
        self.__logging_verbose = logging_verbose

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
    
    def get_logging_verbose(self):
        return self.__logging_verbose
    logging_verbose = property(get_logging_verbose)

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
                self.__event_reporting_wake_interval = config['event_reporting']['wake_interval']
                self.__event_reporting_minimum_count = config['event_reporting']['minimum_count']
                self.__event_reporting_flush_interval = config['event_reporting']['flush_interval']
                self.__event_reporting_trap_exceptions = config['event_reporting']['trap_exceptions']
                self.__logging_verbose = config['logging']['verbose']
        except FileNotFoundError:
            # If file doesn't exist, use defaults
            self.set_defaults()

    def set_defaults(self):
        self.__event_reporting_wake_interval = 10
        self.__event_reporting_minimum_count = 50
        self.__event_reporting_flush_interval = 90
        self.__event_reporting_trap_exceptions = False
        self.__logging_verbose = False

    def __init__(self, config_file = None):

        self.__event_reporting_wake_interval = None
        self.__event_reporting_minimum_count = None
        self.__event_reporting_flush_interval = None
        self.__event_reporting_trap_exceptions = None
        self.__logging_verbose = None

        if (config_file == None):
            from os.path import expanduser
            home = expanduser("~")
            config_file = os.path.join(home, ".ubiq", "configuration")

        if os.path.exists(config_file):
            self.load_config_file(config_file)
        else:
            self.set_defaults()

        configInfo.__init__(self, self.__event_reporting_wake_interval , self.__event_reporting_minimum_count, self.__event_reporting_flush_interval, self.__event_reporting_trap_exceptions, self.__logging_verbose)
