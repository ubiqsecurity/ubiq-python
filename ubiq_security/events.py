import math
import requests
import json
import time
from datetime import datetime, timezone
import threading
import atexit 

from .auth import http_auth
from .version import VERSION
from .configuration import TimestampGranularity

def get_key(api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, user_defined):
    return "api_key='%s' datasets='%s' billing_action='%s' dataset_groups='%s' key_number='%s' dataset_type='%s' user_defined='%s" % (api_key, dataset_name, billing_action, dataset_group_name, key_number, dataset_type, user_defined)

def format_timestamp(timestamp, timestampGranularity):
    dt = datetime(timestamp.year, timestamp.month, timestamp.day, 0, 0, 0, 0, tzinfo=timezone.utc)
    # Apply from least granular to most granular
    # No switch statements till Python 3.10
    if timestampGranularity.value <= TimestampGranularity.HALF_DAYS.value:
        if timestamp.hour >= 12:
            dt = dt.replace(hour=12)
    if timestampGranularity.value <= TimestampGranularity.HOURS.value:
        dt = dt.replace(hour=timestamp.hour)
    if timestampGranularity.value <= TimestampGranularity.MINUTES.value:
        dt = dt.replace(minute=timestamp.minute)
    if timestampGranularity.value <= TimestampGranularity.SECONDS.value:
        dt = dt.replace(second=timestamp.second)
    if timestampGranularity.value <= TimestampGranularity.MILLIS.value:
        dt = dt.replace(microsecond=math.floor(timestamp.microsecond/1000)*1000)
    if timestampGranularity.value <= TimestampGranularity.MICROS.value:
        dt = dt.replace(microsecond=timestamp.microsecond)
    return dt.isoformat()


class event:
    def __init__(self, api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, count, user_defined):
        self.api_key = api_key
        self.dataset_name = dataset_name
        self.dataset_group_name = dataset_group_name
        self.billing_action = billing_action
        self.dataset_type = dataset_type
        self.key_number = key_number
        self.count = count
        self.first_call_timestamp = datetime.now(timezone.utc)
        self.last_call_timestamp = datetime.now(timezone.utc)
        self.user_defined =  user_defined

    def increment_count(self, val):
        self.count = self.count + val
        self.last_call_timestamp = datetime.now(timezone.utc)
        return self.count

    def serialize(self, timestampGranularity, library):
        return {
            'datasets': self.dataset_name,
            'dataset_groups': self.dataset_group_name,
            'dataset_type': self.dataset_type,
            'api_key': self.api_key,
            'count': self.count,
            'key_number': self.key_number,
            'action': self.billing_action,
            'product': library,
            'product_version': VERSION,
            'user-agent': f'{library}/{VERSION}',
            'api_version': 'V3',
            'last_call_timestamp': format_timestamp(self.last_call_timestamp, timestampGranularity),
            'first_call_timestamp': format_timestamp(self.first_call_timestamp, timestampGranularity),
            'user_defined': self.user_defined
        }

class events:
    events_dict = {}
    def __init__(self, creds, config, library = None):
        self.lock = threading.Lock()

        self.config = config

        self._host = creds.host
        if (not self._host.lower().startswith('http')):
            self._host = "https://" + self._host

        self._papi = creds.access_key_id
        self._sapi = creds.secret_signing_key

        self.library = 'ubiq-python'
        if library:
            self.library = library

        self.user_defined = {}

    def add_event(self, api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, count):
        self.lock.acquire()
        try:
            key = get_key(api_key, dataset_name, dataset_group_name,
                         billing_action, dataset_type, key_number, self.user_defined)
            current_count = events.events_dict.get(key, event(api_key, dataset_name, dataset_group_name,
                                                           billing_action, dataset_type, key_number, 0, self.user_defined))
            current_count.increment_count(count)
            events.events_dict.update({key: current_count})
        except Exception as e:
            self.handle_exception(e)
        finally:
            self.lock.release()

    def list_events(self):
        return list(map(lambda e: e.serialize(self.config.get_event_reporting_timestamp_granularity(), self.library), events.events_dict.values()))
    
    def get_events_count(self):
        count = sum(list(map(lambda e: e.count, events.events_dict.values())))
        return count

    def add_user_defined_metadata(self, data):
        if type(data) != str:
            self.handle_exception(Exception('User defined Metadata must be a string.'))
        if len(data) > 1024:
            self.handle_exception(Exception('User defined Metadata cannot be longer than 1024 characters'))

        try:
            parsed_data = json.loads(data)
            self.user_defined = parsed_data
            print("Added user defined metadata: %s" %(data))
        except Exception as e:
            self.handle_exception(Exception('User defined Metadata must be a valid Json object'))
    
    def process_events(self):
        if (self.get_events_count() == 0 or len(events.events_dict) == 0):
            if self.config.get_logging_verbose():
                print('No events, skipping processing.')
            return
        
        if self.config.get_logging_verbose():
            print(f'Processing {self.get_events_count()} events')
        
        self.lock.acquire()

        try:
            usage = json.dumps({'usage': self.list_events()})
            events.events_dict = {}

        except Exception as e:
            self.handle_exception(e)
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
            self.handle_exception(e)
            
    def handle_exception(self, ex):
        if self.config.get_logging_verbose():
                        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
                        message = template.format(type(ex).__name__, ex.args)
                        print(message)
        if self.config.get_event_reporting_trap_exceptions():
            pass
        else:
            raise

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

class syncEventsProcessor:
    def __init__(self, configuration, events):
        self.config = configuration
        self.events = events

        self.flush_interval = self.config.get_event_reporting_flush_interval()
        self.next_flush = time.time() + self.flush_interval

    def process(self):
        if time.time() >= self.next_flush or self.events.get_events_count() >= self.config.get_event_reporting_minimum_count():
            count = self.events.get_events_count()
            self.events.process_events()
            self.next_flush = time.time() + self.flush_interval
            return f"Processed {count} events"
        else: 
            return f"No events processed. Count: {self.events.get_events_count()} Next flush: {self.next_flush}"