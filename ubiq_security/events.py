import requests
import json
import time
from datetime import datetime, timezone
import threading
import atexit 

from .auth import http_auth
from .version import VERSION

def get_key(api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number):
    return "api_key='%s' datasets='%s' billing_action='%s' dataset_groups='%s' key_number='%s' dataset_type='%s'" % (api_key, dataset_name, billing_action, dataset_group_name, key_number, dataset_type)


class event:
    def __init__(self, api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, count):
        self.api_key = api_key
        self.dataset_name = dataset_name
        self.dataset_group_name = dataset_group_name
        self.billing_action = billing_action
        self.dataset_type = dataset_type
        self.key_number = key_number
        self.count = count
        self.first_call_timestamp = datetime.now(timezone.utc).isoformat()
        self.last_call_timestamp = datetime.now(timezone.utc).isoformat()

    def increment_count(self, val):
        self.count = self.count + val
        self.last_call_timestamp = datetime.now(timezone.utc).isoformat()
        return self.count

    def serialize(self):
        return {
            'datasets': self.dataset_name,
            'dataset_groups': self.dataset_group_name,
            'dataset_type': self.dataset_type,
            'api_key': self.api_key,
            'count': self.count,
            'key_number': self.key_number,
            'action': self.billing_action,
            'product': 'ubiq-python',
            'product_version': VERSION,
            'user-agent': 'ubiq-python/' + VERSION,
            'api_version': 'V3',
            'last_call_timestamp': self.last_call_timestamp,
            'first_call_timestamp': self.first_call_timestamp
        }


class events:
    def __init__(self, creds, config):
        self.events_dict = {}
        self.lock = threading.Lock()
        self.count = 0

        self.config = config

        self._host = creds.host
        if (not self._host.lower().startswith('http')):
            self._host = "https://" + self._host

        self._papi = creds.access_key_id
        self._sapi = creds.secret_signing_key

    def add_event(self, api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, count):
        self.lock.acquire()
        try:
            key = get_key(api_key, dataset_name, dataset_group_name,
                         billing_action, dataset_type, key_number)
            current_count = self.events_dict.get(key, event(api_key, dataset_name, dataset_group_name,
                                                           billing_action, dataset_type, key_number, 0))
            current_count.increment_count(count)
            self.events_dict.update({key: current_count})
            self.count += count
        finally:
            self.lock.release()

    def list_events(self):
        return list(map(lambda e: e.serialize(), self.events_dict.values()))
    
    def get_events_count(self):
        return self.count
    
    def process_events(self):
        if self.get_events_count() == 0 and self.config.get_logging_verbose():
            print('No events, skipping processing.')
            return
        
        if self.config.get_logging_verbose():
            print(f'Processing {self.count} events')
        self.lock.acquire()
        try:
            usage = json.dumps({'usage': self.list_events()})
            self.events_dict = {}
            self.count = 0
        finally: 
            self.lock.release()

        try:
            requests.post(f'{self._host}/api/v3/tracking/events',
                        data=usage.encode('utf-8'),
                        auth=http_auth(self._papi, self._sapi)
                        )
            if self.config.get_logging_verbose():
                print(f'Processed events: {usage}')
        except Exception as e:
            if self.config.get_event_reporting_trap_exceptions():
                pass
            else:
                raise e
        


class eventsProcessor:
    def __init__(self, configuration, events):
        self.config = configuration
        self.events = events
        self._processThread = None
        
        self.flush_interval = self.config.get_event_reporting_flush_interval()
        self.next_flush = time.time() + self.flush_interval

        self.wake_interval = self.config.get_event_reporting_wake_interval()
        self.next_wake = time.time() + self.wake_interval

        self.running = False

    def start(self):
        self._processThread = threading.Thread(target=self.process)
        atexit.register(self.graceful_close)
        self._processThread.daemon = True
        self.running = True
        self._processThread.start()

    def process(self):
        while True:
            if not self.running:
                break
            
            # Run every wake
            if time.time() >= self.next_wake:
                # but only submit if events > min or it's flush time
                if self.events.get_events_count() >= self.config.get_event_reporting_minimum_count() or time.time() >= self.next_flush:
                    self.events.process_events()
                    self.next_flush = time.time() + self.flush_interval
                self.next_wake = time.time() + self.wake_interval
            
            time.sleep(self.wake_interval)
        return

    def graceful_close(self):
        if self.config.get_logging_verbose():
            print('Closing event processor')
        self.running = False
        self.events.process_events()
    
    def __del__(self):
        self.graceful_close()