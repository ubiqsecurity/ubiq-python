#!/usr/bin/env python3

import atexit
import configparser
import os
from . import UBIQ_HOST
from .configuration import ubiqConfiguration
from .events import events, eventsProcessor

class credentialsInfo:

    def __init__(self, access_key_id, secret_signing_key, secret_crypto_access_key, host):
        self.__access_key_id = access_key_id
        self.__secret_signing_key = secret_signing_key
        self.__secret_crypto_access_key = secret_crypto_access_key
        self.__host = host

    def get_access_key_id(self):
        return self.__access_key_id
    access_key_id=property(get_access_key_id)

    def get_secret_signing_key(self):
        return self.__secret_signing_key
    secret_signing_key=property(get_secret_signing_key)

    def get_secret_crypto_access_key(self):
        return self.__secret_crypto_access_key
    secret_crypto_access_key = property(get_secret_crypto_access_key)

    def get_host(self):
        return self.__host
    host = property(get_host)

    def set(self):
        return (self.__access_key_id != None and self.__secret_signing_key != None and self.__secret_crypto_access_key != None and 
            self.__access_key_id.strip() != "" and self.__secret_signing_key.strip() != "" and self.__secret_crypto_access_key.strip() != "")

class configCredentials(credentialsInfo):

    def load_config_file(self, config_file, profile):
        config = configparser.ConfigParser()
        config.read(config_file)

        # Create empty dictionaries for the default and supplied profile
        d = {}
        p = {}

        # get the default profile if there is one
        if (config.has_section('default')):
            d = config['default']

        # get the supplied profile if there is one
        if (config.has_section(profile)):
            p = config[profile]

        # Use given profile if it is available, otherwise use default.
        self.__access_key_id= p.get('access_key_id', d.get('access_key_id'))
        self.__secret_signing_key = p.get('secret_signing_key', d.get('secret_signing_key'))
        self.__secret_crypto_access_key = p.get('secret_crypto_access_key', d.get('secret_crypto_access_key'))
        self.__host = p.get('SERVER', d.get('SERVER', UBIQ_HOST))


    def __init__(self, config_file = None, profile = "default"):

        self.__access_key_id = None
        self.__secret_signing_key = None
        self.__secret_crypto_access_key = None
        self.__host = None

        if (config_file == None):
            from os.path import expanduser
            home = expanduser("~")
            config_file = os.path.join(home, ".ubiq", "credentials")

        if os.path.exists(config_file):
            self.load_config_file(config_file, profile)

        credentialsInfo.__init__(self, self.__access_key_id , self.__secret_signing_key, self.__secret_crypto_access_key, self.__host)

        if (not self.set()):
            if (self.__access_key_id == None or self.__access_key_id.strip() == ""):
               raise RuntimeError("Unable to open credentials file '{0}' or unable to find 'access_key_id' value in profile '{1}' or through environment variable for 'UBIQ_ACCESS_KEY_ID'.".format(config_file, profile))
            elif (self.__secret_signing_key == None or self.__secret_signing_key.strip() == ""):
               raise RuntimeError("Unable to open credentials file '{0}' or unable to find 'secret_signing_key' value in profile '{1}' or through environment variable for 'UBIQ_SECRET_SIGNING_KEY'.".format(config_file, profile))
            elif(self.__secret_crypto_access_key == None or self.__secret_crypto_access_key.strip() == ""):
               raise RuntimeError("Unable to open credentials file '{0}' or unable to find 'secret_crypto_access_key' value in profile '{1}' or through environment variable for 'UBIQ_SECRET_CRYPTO_ACCESS_KEY'.".format(config_file, profile))
        
        # Event Tracking
        self.__configuration = ubiqConfiguration()
        self.__events = events(self, self.__configuration)
        self.__eventsProcessor = eventsProcessor(self.__configuration, self.__events)
        self.__eventsProcessor.start()

    # Forward events to event queue
    def add_event(self, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, count):
        return self.__events.add_event(self.__access_key_id, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, count)


class credentials(credentialsInfo):

    def __init__(self, access_key_id = None, secret_signing_key = None, secret_crypto_access_key = None, host = UBIQ_HOST):
        # If supplied value is None, use ENV variable, otherwise use supplied value.
        # If env value isn't set, use the supplied value anyways (None) but prevent an exception
        self.__access_key_id = (access_key_id, os.getenv('UBIQ_ACCESS_KEY_ID', access_key_id)) [access_key_id == None]
        self.__secret_signing_key = (secret_signing_key, os.getenv('UBIQ_SECRET_SIGNING_KEY', secret_signing_key)) [secret_signing_key == None]
        self.__secret_crypto_access_key = (secret_crypto_access_key, os.getenv('UBIQ_SECRET_CRYPTO_ACCESS_KEY', secret_crypto_access_key)) [secret_crypto_access_key == None]

        credentialsInfo.__init__(self, self.__access_key_id,
                                 self.__secret_signing_key,
                                 self.__secret_crypto_access_key, host)
        
        # Event Tracking
        self.__configuration = ubiqConfiguration()
        self.__events = events(self, self.__configuration)
        self.__eventsProcessor = eventsProcessor(self.__configuration, self.__events)
        self.__eventsProcessor.start()
    
    # Forward events to event queue
    def add_event(self, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, count):
        return self.__events.add_event(self.__access_key_id, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, count)
