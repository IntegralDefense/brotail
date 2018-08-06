#!/usr/bin/env python3
import argparse
import collections
import gc
import glob
import json
import logging
import logging.config
import multiprocessing
import os
import os.path
import pprint
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse

from configparser import ConfigParser
from datetime import datetime

from saq.client import Alert
from saq.constants import *

# pip install iptools
from iptools import IpRangeList

# brotail home directory
BROTAIL_ENV_VAR = 'BROTAIL_HOME'
BASE_DIRECTORY = '/opt/brotail' # default value

# program arguments
args = None

# global config
config = None

# whitelist configuration
whitelist = None

# regex patterns
dns_regex = re.compile('^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$')
ipv4_regex = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

def extract_observable_ipv4(value):
    return value

class WhitelistPattern(object):
    def __init__(self, name, log, patterns):
        self.name = name
        self.log = log
        self.patterns = patterns # dict(key = field_name, value = pattern)
        for key in self.patterns.keys():
            # a pattern can be a string or a IpRangeList object if it's prefixed with cidr:
            self.patterns[key] = [IpRangeList(x[5:]) if x.startswith('cidr:') else x for x in self.patterns[key].split(',')]

    def __str__(self):
        return self.name

    def matches(self, entry):
        """Returns True if this pattern matches this entry.  The entry is the dict of the bro data."""
        for field_name in self.patterns.keys():
            if field_name not in entry:
                logging.error("log {} missing field {}".format(self.log, field_name))

            values = self.patterns[field_name]
            matches_any = False
            for value in values:
                # note that the "in" keyword here works for both string and IpRangeList objects
                # which value will be one of those two types
                if entry[field_name] in value:
                    matches_any = True
                    #logging.debug("{} matches whitelist item {}".format(entry[field_name], value))
                    break

            if not matches_any:
                return False

        return True

class CRITSProxy(object):
    def __init__(self):
        # the main repository of stuff to look for
        self.crits = {} # key = indicator type, value = [] of crits indicators (of type dict)
        self.fast_lookup_table_nocase = {} # key = indicator type, value = { key = value, value = [ crits_indicator ] }
        self.fast_lookup_table = {} # key = indicator type, value = { key = value, value = [ crits_indicator ] }
        self.fast_lookup_table_dns = {}
        self.parsed_urls = [] # list of parsed urls with an additional attribute called "indicator" that is a reference to the crits indicator
        # fast_lookup_dns works like this: consider evil.com, hacker.com, and su when looking for c2.evil.com, google.com and savepic.su
        # t['com']['evil'] = indicator
        # t['com']['hacker'] = indicator
        # t['su'] = indicator
        # basic idea:
        # 1) look up root --> does it exist?  yes --> is it an indicator?  yes --> done
        # 2) otherwise it's another dictionary
        # 3) continue
        # c2.evil.com
        # 1) lookup 'com' --> it exists and it's a dict, continue
        # 2) do we have any more to lookup? yes, continue
        # 3) lookup 'evil' in 'com' --> it exists and it is an indicator --> done
        # google.com
        # 1) lookup 'com' --> it exists and it's a dict, continue
        # 2) do we have any more to lookup? yes, continue
        # 3) lookup 'google' --> KeyError --> done
        # savepic.su
        # 1) lookup 'su' --> it's an indicator --> done

        self.update_thread = None # used to keep the intel up to date
        self.last_mtime = None # the last modification time of the intel file

    def start(self):
        # update before we return from start() so we can start using it right away
        try:
            self.update()
        except Exception as e:
            logging.error("unable to update crits: {}".format(str(e)))
            report_exception()

        self.update_thread = threading.Thread(target=self.run, name='CRITS Update Thread')
        self.update_thread.daemon = True
        self.update_thread.start()

    def stop(self):
        pass

    def run(self):
        while True:
            # update every N seconds
            time.sleep(int(config['crits']['update_interval']))
            self.update()

    def update(self):
        crits = {}
        lookup_table = {}
        lookup_table_nocase = {}
        lookup_table_dns = {}
        parsed_urls = []

        # the JSON we load from the crits export
        # key = indicator_type, value [ crits_indicator_json ]
        crits_json = {}

        try:
            #logging.debug("connecting to mongo server {}".format(config['crits']['host']))
            #connection = MongoClient(config['crits']['uri'])
            #connection = MongoClient('mongodb://{}:{}'.format(config['crits']['host'], config['crits']['port']))
            #logging.debug("connecting to mongo database {}".format(config['crits']['db']))
            #db = connection[config['crits']['db']]

            # has the file changed?
            mtime = os.path.getmtime(config['crits']['path'])
            if mtime != self.last_mtime:
                logging.debug("detected change in {}".format(config['crits']['path']))
                self.last_mtime = mtime
            else:
                return

            # load the file as a json file
            with open(config['crits']['path'], 'r') as fp:
                crits_json = json.load(fp)

            indicator_types = crits_json.keys()
            #indicator_types = db.object_types.find({"active": "on"})

            for indicator_type in indicator_types:
                #indicator_type = row['type']

                logging.debug("importing indicator type {}".format(indicator_type))
                #collection = db.indicators.find({"status": "Analyzed", "type": indicator_type})

                data = []
                lookup_table[indicator_type] = {}
                lookup_table_nocase[indicator_type] = {}

                for item in crits_json[indicator_type]:
                #for item in collection:
                    data.append(item)
                    indicator_value = item['value']

                    if indicator_value not in lookup_table[indicator_type]:
                        lookup_table[indicator_type][indicator_value] = []
                    lookup_table[indicator_type][indicator_value].append(item)

                    indicator_value_nocase = item['value'].lower()
                    if indicator_value_nocase not in lookup_table_nocase[indicator_type]:
                        lookup_table_nocase[indicator_type][indicator_value_nocase] = []
                    lookup_table_nocase[indicator_type][indicator_value_nocase].append(item)

                    if indicator_type == 'URI - URL' or indicator_type == 'URI - Path':
                        try:
                            parsed_url = urllib.parse.urlparse(item['value'])
                            parsed_urls.append((parsed_url, item))
                        except Exception as e:
                            logging.warning("unable to parse crits url {} from indicator {}: {}".format(
                                item['value'], item['_id'], str(e)))

                    if indicator_type == 'URI - Domain Name':
                        fqdn_parts = indicator_value_nocase.split('.')
                        fqdn_parts.reverse()

                        # make sure this is a valid fqdn
                        valid = True

                        # make sure this isn't an IP address
                        if ipv4_regex.match(indicator_value_nocase) is not None:
                            logging.debug("fqdn {} for indicator {} looks like an ip address".format(
                                indicator_value_nocase, item['_id']))
                            valid = False

                        if valid:
                            for part in fqdn_parts:
                                if dns_regex.match(part) is None:
                                    logging.debug("skipping invalid fqdn {} in indicator {}".format(
                                        indicator_value_nocase, item['_id']))
                                    valid = False
                                    break
                        if valid:
                            table_target = lookup_table_dns
                            for index, part in enumerate(fqdn_parts):
                                # we're building out the hash tree until we get to the last node
                                if index < len(fqdn_parts) - 1:
                                    try:
                                        table_target = table_target[part]
                                        # did we hit an indicator?
                                        if not isinstance(table_target, dict):
                                            logging.debug("ignoring fqdn indicator {} since {} already exists".format(
                                                indicator_value_nocase, table_target[0]['value']))
                                            break

                                    except KeyError:
                                        table_target[part] = {}
                                        table_target = table_target[part]
                                # last node is the indicator
                                else:
                                    # something already here?
                                    if part in table_target:
                                        if isinstance(table_target[part], dict):
                                            logging.debug("fqdn indicator {} replaces existing indicators as a subdomain match".format(
                                                indicator_value_nocase))
                                            table_target[part] = [ item ]
                                        else:
                                            logging.debug("duplicate indicator value for fqdn {}".format(indicator_value_nocase))
                                    else:
                                        table_target[part] = [ item ]

                logging.debug("imported indicator type {} count {}".format(indicator_type, len(data)))
                crits[indicator_type] = data

        except Exception as e:
            logging.error("uncaught exception when importing crits data: {}".format(str(e)))
            report_exception()
            return False

        if config['crits'].getboolean('dump_lookup_tables'):
            # write these files out to disk for debugging purposes
            try:
                #with open(os.path.join(base_directory, 'var', 'fast_lookup'), 'w') as fp:
                    #pprint.pprint(lookup_table, stream=fp, indent=4)
                #with open(os.path.join(base_directory, 'var', 'fast_lookup_nocase'), 'w') as fp:
                    #pprint.pprint(lookup_table_nocase, stream=fp, indent=4)
                with open(os.path.join(BASE_DIRECTORY, 'var', 'fast_lookup_dns'), 'w') as fp:
                    pprint.pprint(lookup_table_dns, stream=fp, indent=4)
            except Exception as e:
                logging.warning("unable to write out lookup tables to var: {}".format(str(e)))

        # quickly change the pointers
        self.crits = crits
        self.fast_lookup_table = lookup_table
        self.fast_lookup_table_nocase = lookup_table_nocase
        self.fast_lookup_table_dns = lookup_table_dns
        self.parsed_urls = parsed_urls

        # run GC since we're dealing with very large lists
        unreachable_count = gc.collect()
        logging.debug("freed {} items with gc".format(unreachable_count))
        
        return True

    def check_indicator_type(self, indicator_type):
        if indicator_type not in self.crits:
            logging.warning("missing indicator type {}".format(indicator_type))
            return False

        return True

    def fast_lookup(self, indicator_type, value):
        if not self.check_indicator_type(indicator_type):
            return []
        
        try:
            return self.fast_lookup_table[indicator_type][value]
        except KeyError:
            return []

    def fast_lookup_dns(self, value):
        parts = value.strip().lower().split('.')
        parts.reverse()

        node = self.fast_lookup_table_dns

        for part in parts:
            try:
                #logging.debug("looking up part {}".format(part))
                node = node[part]
                if isinstance(node, dict):
                    continue

                return node

            except KeyError:
                return []

        return []

    def fast_lookup_nocase(self, indicator_type, value):
        if not self.check_indicator_type(indicator_type):
            return []

        try:
            return self.fast_lookup_table_nocase[indicator_type][value.lower()]
        except KeyError:
            return []

    def slow_lookup(self, indicator_type, value):
        if not self.check_indicator_type(indicator_type):
            return []

        result = []
        for indicator in self.crits[indicator_type]:
            if indicator['value'].strip() in value:
                result.append(indicator)

        return result

    def slow_lookup_nocase(self, indicator_type, value):
        if not self.check_indicator_type(indicator_type):
            return []

        result = []
        for indicator in self.crits[indicator_type]:
            if indicator['value'].strip().lower() in value.lower():
                result.append(indicator)

        return result

class Brotail(object):
    def __init__(self, log_file):
        self.log_file = log_file
        self.log_file_path = os.path.join(config['bro']['bro_dir'], self.log_file)
        self.pid_file = os.path.join(BASE_DIRECTORY, 'var', '{}.pid'.format(os.path.basename(log_file)))

        self.tail = None # Popen object
        self.tail_thread = None # thread
        self.tail_stdout_thread = None
        self.tail_stderr_thread = None
        self.queue = queue.Queue(1000) # figure out what works best here...
        self.separator = None
        self.set_separator = None
        self.empty_field = None
        self.unset_field = None
        self.path = None
        self.open_time = None
        self.fields = None
        self.types = None
        self.header_lines = 0 # the total number of lines read in the header

        self.process = None # subprocess.Process
        self.shutdown = False # set to True in the signal handler when SIGTERM is received
        self.reload_configuration = False # set to True in the signal handler when SIGHUP is received

        self.crits_proxy = None # CRITSScanner
        
        # stats
        self.last_timestamp_scanned = None # the last timestamp that was scanned
        self.stats_thread = None
        self.entries_scanned = 0

        # used when debuggin
        self.trigger_flag = False

        # a little bit of a hack here...
        self.aggregation_queue = {} # key = alert.description, value = tuple(datetime.datetime.now(), [] of Alert objects)

    def __str__(self):
        return 'brotail({})'.format(self.log_file)

    def start(self):
        # delete the existing pid and control files
        if os.path.exists(self.pid_file):
            logging.debug("removing existing pid file {}".format(self.pid_file))
            try:
                os.remove(self.pid_file)
            except Exception as e:
                logging.fatal("unable to remove pid file {}: {}".format(self.pid_file, str(e)))
                sys.exit(1)

        self.process = multiprocessing.Process(target=self.run)
        self.process.start()
    
    def wait(self):
        logging.debug("{} wait process".format(self))
        self.process.join() # wait for the subprocess to die...
        logging.debug("{} wait process completed".format(self))

    def stop(self):
        self.shutdown = True

        try:
            logging.debug("requestiong termination of {}".format(self.process))
            self.process.terminate()
            self.process.join(5)
        except Exception as e:
            logging.error("unable to terminate process {}: {}".format(self.process, str(e)))

        try:
            if self.process.is_alive():
                logging.error("unable to terminate {} -- killing".format(self.process))
                self.process.kill()
        except Exception as e:
            logging.error("unable to kill process {}: {}".format(self.process, str(e)))

    def aggregate_alert(self, alert):
        if alert.description not in self.aggregation_queue:
            self.aggregation_queue[alert.description] = (datetime.now(), [])

        self.aggregation_queue[alert.description][1].append(alert)
        logging.info("queued alert {} for aggregation".format(alert))

    def check_aggregation_queue(self):
        submitted_keys = []
        #logging.debug("checking aggregation queue...")
        for key in self.aggregation_queue.keys():
            queue_ctime, queue = self.aggregation_queue[key]
            # if we're shutting down OR the first alert is older than X seconds...
            if len(queue) == 0:
                continue

            #logging.debug("queue {} age {}".format(key, (datetime.now() - queue_ctime).total_seconds()))

            if self.shutdown or (datetime.now() - queue_ctime).total_seconds() > config['ace'].getint('aggregation_time'):

                logging.info("submitting {} alerts of {}".format(len(queue), key))

                # merge these all together and send as one alert
                # create an ACE alert
                alert = Alert(
                    tool = queue[0].tool,
                    tool_instance = queue[0].tool_instance,
                    alert_type = queue[0].alert_type,
                    desc = 'brotail detection on {} ({} times)'.format(key, len(queue)),
                    # base the time on the file time preserved by tar
                    event_time=queue[0].event_time,
                    details=[a.details for a in queue])

                for a in queue:
                    for o_type in a.observables.keys():
                        for (o_value, o_time, is_suspect, directives) in a.observables[o_type]:
                            alert.add_observable(o_type, o_value, o_time)
                    alert.tags = alert.tags | a.tags # union

                try:
                    alert.submit(config['ace']['uri'], config['ace']['key'])
                except Exception as e:
                    logging.error("unable to submit alert {}: {}".format(alert, str(e)))

                submitted_keys.append(key)

        for key in submitted_keys:
            del self.aggregation_queue[key]

    def run(self):
        # prepare signal handlers
        def signal_handler_sigterm(signum, frame):
            self.shutdown = True
        def signal_handler_sighup(signum, frame):
            self.reload_configuration = True

        signal.signal(signal.SIGTERM, signal_handler_sigterm)
        signal.signal(signal.SIGHUP, signal_handler_sighup)
        
        # write our PID to the var/ subdir
        with open(self.pid_file, 'w') as pid_fp:
            logging.debug("{} has pid {}".format(self, self.process.pid))
            pid_fp.write('{}'.format(self.process.pid))

        # load the mapping from bro field to indicator type
        self.bro_type_mapping = {}
        for option in config['bro_type_mapping'].keys():
            self.bro_type_mapping[option] = config['bro_type_mapping'][option]

        # map the indicator type to the function that will be used to scan
        self.indicator_scanners = {
            'ipv4': self.scan_ipv4,
            'ipv4_vector': self.scan_ipv4_vector,
            'fqdn': self.scan_fqdn,
            'url': self.scan_url,
            'user_agent': self.scan_useragent,
            'filename': self.scan_filename,
            'md5': self.scan_md5,
            'sha1': self.scan_sha1,
            'sha256': self.scan_sha256,
            'email_address': self.scan_email_address,
            'email_address_vector': self.scan_email_address_vector,
            'email_subject': self.scan_email_subject,
            'email_mailer': self.scan_email_mailer
        }

        # starts the crits scanner
        self.crits_proxy = CRITSProxy()
        self.crits_proxy.start()

        # wait for the intel to be loaded
        while not self.shutdown and len(self.crits_proxy.crits) < 1:
            logging.info("waiting for crits intelligence to load...")
            time.sleep(1)

        if self.shutdown:
            return

        # start a stats thread
        self.stats_thread = threading.Thread(target=self.manage_statistics, name="{} stats thread".format(self))
        self.stats_thread.daemon = True
        self.stats_thread.start()

        # wait for the target log file to appear (it may not ever)
        logging.debug("checking for {}".format(self.log_file_path))
        while not self.shutdown:
            if os.path.exists(self.log_file_path):
                break

            time.sleep(1)

        if self.shutdown:
            return

        logging.debug("found {}".format(self.log_file_path))

        # initialize from the bro log file
        try:
            self.initialize()
        except Exception as e:
            logging.fatal("unable to initialize {}: {}".format(self, str(e)))
            report_exception()
            return

        # start the tail process that will forever run
        try:
            self.start_tail()
        except Exception as e:
            logging.fatal("unable to start the tail on {}: {}".format(self, str(e)))
            report_exception()
            return

        initialize_whitelist()
            
        while not self.shutdown:
            if self.reload_configuration:
                self.reload_configuration = False
                initialize_whitelist()

            try:
                self.execute()
            except KeyboardInterrupt:
                break
            except Exception as e:
                logging.error("uncaught exception: {}".format(str(e)))
                report_exception()
                time.sleep(1)

        # make sure subprocess is dead
        self.stop_tail()

        # make sure we've sent all the alerts we've got
        self.check_aggregation_queue()

        logging.info("{} shutdown complete".format(self))

    def manage_statistics(self):
        last_second = 0
        average_total = 0
        average_counter = 0
        average_per_second = 0

        while True:
            current_entries_scanned = self.entries_scanned
            events_last_second = self.entries_scanned - last_second
            average_total += events_last_second
            average_counter += 1
            last_second = current_entries_scanned

            if average_counter == 60:
                average_counter = 0
                average_per_second = float(average_total) / 60.0

            if self.path:
                with open(os.path.join(BASE_DIRECTORY, 'var', '{}.stats'.format(self.path)), 'w') as stats_fp:
                    stats_fp.write("scanner = {}\n".format(self))
                    stats_fp.write("last timestamp scanned = {}\n".format(self.last_timestamp_scanned))
                    stats_fp.write("total events processes = {}\n".format(current_entries_scanned))
                    stats_fp.write("events last second = {}\n".format(events_last_second))
                    stats_fp.write("average per second = {:.2f}\n".format(average_per_second))

            if average_counter == 0:
                logging.info("scanner = {} "
                    "last timestamp scanned = {} "
                    "total events processes = {} "
                    "events last second = {} "
                    "average per second = {:.2f}".format(
                    self, 
                    self.last_timestamp_scanned, 
                    current_entries_scanned, 
                    events_last_second, 
                    average_per_second))

            time.sleep(1)

    def execute(self):
        try:
            self.check_aggregation_queue()
        except Exception as e:
            logging.error("unable to check aggregation queue: {}".format(str(e)))
            report_exception()

        # get the next thing to check
        try:
            entry = self.queue.get(True, 1)
        except queue.Empty:
            #logging.debug("{} has no entries".format(self))
            return False
        except KeyboardInterrupt:
            return True

        #if not self.trigger_flag:
            #self.trigger_flag = True
            #entry['mailfrom'] = 'nick@westcentralauction.net'

        # process this thing
        results = self.scan(entry)
        if args.debug_alerts or len(results) > 0:
            logging.debug("entry returned {} results".format(len(results)))
            for result in results:
                logging.debug(result)

            self.send_ace_alert(entry, results)

        # mark when the last timestamp was scanned
        if 'ts' in entry:
            self.last_timestamp_scanned = datetime.fromtimestamp(float(entry['ts']))

        self.entries_scanned += 1
        return True

    def start_tail(self):
        self.tail_thread = threading.Thread(target=self.tail_log_file, name="{} subprocess".format(self))
        self.tail_thread.start()

    def stop_tail(self):
        try:
            if self.tail:
                logging.debug("killing subprocess")
                self.tail.kill()
        except Exception as e:
            logging.error("error killing subprocess: {}".format(str(e)))

        self.tail = None

    def tail_log_file(self):
        while not self.shutdown:
            try:
                # wait for this file to become available
                if not os.path.exists(self.log_file_path):
                    logging.debug("waiting for {} to become available".format(self.log_file_path))
                    time.sleep(1)
                    continue

                #self.tail = subprocess.Popen(['tail', '-n', '+{}'.format(self.header_lines), '-F', self.log_file_path], stdout=subprocess.PIPE)
                self.tail = subprocess.Popen(['tail', '-f', self.log_file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # we start separate threads for reading stdin and stdout
                # these can be shutdown by either setting the shutdown property to True
                # or by setting this following event object, which gets passed in to each thread
                thread_shutdown_event = threading.Event()
                self.tail_stdout_thread = threading.Thread(target=self.tail_stdout_reader, args=(thread_shutdown_event,), name="tail stdout reader {}".format(self.log_file_path))
                self.tail_stdout_thread.start()

                self.tail_stderr_thread = threading.Thread(target=self.tail_stderr_reader, args=(thread_shutdown_event,), name="tail stderr reader {}".format(self.log_file_path))
                self.tail_stderr_thread.start()

                # spin until either one of these threads are dead
                while not self.shutdown and not thread_shutdown_event.is_set():
                    if not self.tail_stdout_thread.is_alive():
                        break

                    if not self.tail_stderr_thread.is_alive():
                        break

                    time.sleep(1)

                logging.debug("stopping threads for {}".format(self.log_file_path))

                # signal the threads to die
                thread_shutdown_event.set()

                # kill the tail process
                try:
                    self.tail.kill()
                except Exception as e:
                    logging.error("unable to kill process {}: {}".format(self.tail, str(e)))

                # wait for the threads to die
                try:
                    self.tail_stdout_thread.join()
                except Exception as e:
                    logging.error("join failed on stdout reader thread for {}: {}".format(self.log_file_path, str(e)))

                try:
                    self.tail_stderr_thread.join()
                except Exception as e:
                    logging.error("join failed on stderr reader thread for {}: {}".format(self.log_file_path, str(e)))

            except Exception as e:
                logging.error("uncaught exception tailing log file: {}".format(str(e)))
                report_exception()
                time.sleep(1)

            self.tail = None

    def tail_stdout_reader(self, thread_shutdown_event):
        try:
            while not self.shutdown and not thread_shutdown_event.is_set():
                line = self.tail.stdout.readline().decode()
                if line == '':
                    logging.info("detected EOF on tail process {}".format(self.tail))
                    return

                if line.startswith('#close'):
                    # tail detected the file closed - need to restart
                    logging.info("detected closed file on {}".format(self.tail))
                    return

                if line.startswith('#'):
                    continue

                row = line.split(self.separator)
                if len(row) != len(self.fields):
                    logging.warning("the length of the row ({}) does not match the lenght of the fields ({})".format(
                        len(row), len(self.fields)))
                    try:
                        with open(os.path.join(BASE_DIRECTORY, 'logs', '{}.corrupted_entries'.format(self.path)), 'a') as fp:
                            fp.write(line)
                    except:
                        pass

                    continue

                # build a little dictionary to pass to the queue
                # key = field_name, value = value
                entry = {}
                for index, value in enumerate(row):
                    entry[self.fields[index]] = value

                self.queue.put(entry)
        except Exception as e:
            logging.error("unable to read from stdout on {}: {}".format(self.log_file_path, str(e)))
            return

        finally:
            # indicate that the threads are shutting down
            thread_shutdown_event.set()

    def tail_stderr_reader(self, thread_shutdown_event):
        try:
            while not self.shutdown and not thread_shutdown_event.is_set():
                line = self.tail.stderr.readline().decode().strip()
                if line == '':
                    logging.info("detected EOF on tail process {}".format(self.tail))
                    return

                logging.error("{}".format(line))

                # tail outputs this error message when the file becomes completely lost
                # in this case we need to restart tail
                if 'has become inaccessible' in line:
                    logging.warning("detected loss of file")
                    return

        except Exception as e:
            logging.warning("reading from stderr failed: {}".format(str(e)))
            return

        finally:
            thread_shutdown_event.set()

    def initialize(self):
        # load the bro log file
        self.fp = open(self.log_file_path, 'r')
        self.header_lines = 0

        # read the header information
        ### separator
        line = self.fp.readline().strip()
        self.header_lines += 1
        m = re.match(r'^#separator\s+\\x([0-9a-fA-F]+)$', line)
        if not m:
            logging.fatal("unable to read separator from {} for {}".format(
                line, self))
            return False

        self.separator = chr(int(m.group(1), 16)) # in base 16

        ### set_separator
        line = self.fp.readline().strip()
        self.header_lines += 1
        m = re.match(r'^#set_separator\s+(\S+)$', line)
        if not m:
            logging.fatal("unable to read set_separator from {} for {}".format(
                line, self))
            return False

        self.set_separator = m.group(1)

        ### empty_field
        line = self.fp.readline().strip()
        self.header_lines += 1
        m = re.match(r'^#empty_field\s+(\S+)$', line)
        if not m:
            logging.fatal("unable to read empty_field from {} for {}".format(
                line, self))
            return False

        self.empty_field = m.group(1)

        ### unset_field
        line = self.fp.readline().strip()
        self.header_lines += 1
        m = re.match(r'^#unset_field\s+(\S+)$', line)
        if not m:
            logging.fatal("unable to read unset_field from {} for {}".format(
                line, self))
            return False

        self.unset_field = m.group(1)

        ### path
        line = self.fp.readline().strip()
        self.header_lines += 1
        m = re.match(r'^#path\s+(\S+)$', line)
        if not m:
            logging.fatal("unable to read path from {} for {}".format(
                line, self))
            return False

        self.path = m.group(1)

        ### open
        self.header_lines += 1
        line = self.fp.readline().strip()
        m = re.match(r'^#open\s+(\S+)$', line)
        if not m:
            logging.fatal("unable to read open from {} for {}".format(
                line, self))
            return False

        self.open_time = m.group(1)

        ### fields
        line = self.fp.readline().strip()
        self.header_lines += 1
        m = re.match(r'^#fields\s+(\S.+)$', line)
        if not m:
            logging.fatal("unable to read fields from {} for {}".format(
                line, self))
            return False

        self.fields = m.group(1).split(self.separator)

        ### types
        line = self.fp.readline().strip()
        self.header_lines += 1
        m = re.match(r'^#types\s+(\S.+)$', line)
        if not m:
            logging.fatal("unable to read types from {} for {}".format(
                line, self))
            return False

        self.types = m.group(1).split(self.separator)

        logging.info("{} "
            "separator {} "
            "set_separator {} "
            "empty_field {} "
            "unset_field {} "
            "path {} "
            "open {}".format(
            self,
            hex(ord(self.separator)),
            self.set_separator,
            self.empty_field,
            self.unset_field,
            self.path,
            self.open_time))

        for index, field in enumerate(self.fields):
            logging.info("{} field {} name {} type {}".format(
                self, index, field, self.types[index]))

        return True

    def scan(self, entry):
        """Scan a given bro log file entry with the CRITS indicators.  Returns a list of CRITS indicators that match."""
        # source_type == Brotail.path (http, files, etc...)
        # entry = { key = field_name, value = value }
        if whitelist is not None:
            if self.log_file in whitelist:
                for whitelist_item in whitelist[self.log_file]:
                    if whitelist_item.matches(entry):
                        logging.debug("whitelist pattern {} matches entry {}".format(whitelist_item, entry))
                        return [] # return emtpy result

        result = []
        for field_name in entry.keys():
            # do we have a type mapping for this field?
            field_key = '{}!{}'.format(self.path, field_name)
            #logging.debug("looking up {}".format(field_key))
            try:
                indicator_type = self.bro_type_mapping[field_key]
            except KeyError:
                continue

            #logging.debug("field_key {} has indicator type = {}".format(field_key, indicator_type))
            try:
                scanning_function = self.indicator_scanners[indicator_type]
            except KeyError:
                logging.fatal("missing scanning function for indicator type {}".format(indicator_type))
                return []

            #logging.debug("scanning indicator with {}".format(scanning_function.__name__))
            scan_result = scanning_function(entry[field_name])
            if scan_result:
                result.extend(scan_result)

        return result

    def scan_ipv4(self, value):
        return self.crits_proxy.fast_lookup('Address - ipv4-addr', value.strip())

    def scan_ipv4_vector(self, value):
        result = []
        for ipv4 in value.split(self.set_separator):
            result.extend(self.crits_proxy.fast_lookup('Address - ipv4-addr', ipv4.strip()))
        return result

    def scan_fqdn(self, value):
        return self.crits_proxy.fast_lookup_dns(value.strip())

    def scan_url(self, value):
        try:
            bro_url = urllib.parse.urlparse(value)
        except Exception as e:
            logging.warning("unable to parse url {}: {}".format(value, str(e)))
            return []

        result = []

        for crits_url, indicator in self.crits_proxy.parsed_urls:
            if crits_url.scheme != '' and crits_url.scheme.lower() != bro_url.scheme.lower():
                #if value == 'http://evil.hacker.com/tmp.swf':
                    #logging.info("MARKER 1")
                continue

            if crits_url.netloc != '' and crits_url.netloc.lower() != bro_url.netloc.lower():
                #if value == 'http://evil.hacker.com/tmp.swf':
                    #logging.info("MARKER 2 {}".format(crits_url.netloc))
                continue

            if crits_url.path != '' and crits_url.path.lower() not in bro_url.path.lower():
                #if value == 'http://evil.hacker.com/tmp.swf':
                    #logging.info("MARKER 3 {}".format(crits_url.path))
                continue

            if crits_url.query != '' and crits_url.query.lower() not in bro_url.query.lower():
                #if value == 'http://evil.hacker.com/tmp.swf':
                    #logging.info("MARKER 4 {}".format(crits_url.query))
                continue

            if crits_url.fragment != '' and crits_url.fragment.lower() not in bro_url.fragment.lower():
                #if value == 'http://evil.hacker.com/tmp.swf':
                    #logging.info("MARKER 5 {}".format(crits_url.fragment))
                continue

            result.append(indicator)

        return result

    def scan_useragent(self, value):
        return self.crits_proxy.fast_lookup_nocase('URI - HTTP - UserAgent', value.strip())

    def scan_filename(self, value):
        return self.crits_proxy.fast_lookup_nocase('Windows - FileName', value.strip())

    def scan_md5(self, value):
        return self.crits_proxy.fast_lookup_nocase('Hash - MD5', value.strip())

    def scan_sha1(self, value):
        return self.crits_proxy.fast_lookup_nocase('Hash - SHA1', value.strip())

    def scan_sha256(self, value):
        return self.crits_proxy.fast_lookup_nocase('Hash - SHA256', value.strip())

    def scan_email_address(self, value):
        return self.crits_proxy.slow_lookup_nocase('Email - Address', value.strip())

    def scan_email_address_vector(self, value):
        result = []
        for email_address in value.lower().split(self.set_separator):
            result.extend(self.crits_proxy.slow_lookup_nocase('Email - Address', value.strip()))
        return result

    def scan_email_subject(self, value):
        return self.crits_proxy.slow_lookup_nocase('Email - Subject', value.strip())

    def scan_email_mailer(self, value):
        return self.crits_proxy.slow_lookup_nocase('Email - Xmailer', value.strip())

    def send_ace_alert(self, entry, results):
        # create an ACE alert
        alert = Alert(
            tool='brotail', 
            tool_instance=socket.gethostname(),
            alert_type='brotail - {} - {}'.format(self.path, ','.join([x['value'] for x in results])),
            desc='brotail detection on {}'.format(self.path),
            # base the time on the file time preserved by tar
            event_time=time.strftime(event_time_format, time.localtime(float(entry['ts']))),
            details=entry)

        for result in results:
            alert.add_observable(F_INDICATOR, str(result['_id']))

        # for each field see if we have a bro_type_mapping entry
        for field_name in entry.keys():
            field_key = '{}!{}'.format(self.path, field_name)
            bro_type = config['bro_type_mapping'].get(field_key, None)
            if bro_type is None:
                continue

            field_type = config['field_type_observables'].get(bro_type, None)
            if field_type is None:
                continue

            if field_type.startswith('set:'):
                _, observable_type = field_type.split(':')
                for value in entry[field_name].split(self.set_separator):
                    if value != self.empty_field and value != self.unset_field:
                        alert.add_observable(observable_type, value, o_time=time.strftime(event_time_format, time.localtime(float(entry['ts']))))
            else:
                if entry[field_name] != self.empty_field and entry[field_name] != self.unset_field:
                    alert.add_observable(field_type, entry[field_name], o_time=time.strftime(event_time_format, time.localtime(float(entry['ts']))))

        # we also have some custom stuff for each bro source type
        if self.path == 'conn' or self.path == 'dns' or self.path == 'http' or self.path == 'ftp':
            alert.add_observable(
                F_IPV4_CONVERSATION, 
                create_ipv4_conversation(entry['id.orig_h'], entry['id.resp_h']), 
                o_time=time.strftime(event_time_format, time.localtime(float(entry['ts']))))
                
        #for indicator_type in config['crits_observable_mapping'].keys():
            #if result['type'].lower() == indicator_type.lower():
                #alert.add_observable(config['crits_observable_mapping'][indicator_type], result['value'])

        alert.description = '{} ({})'.format(alert.description, ','.join(list(set([x['value'] for x in results]))))

        #logging.info("submitting alert {} to {}".format(alert, config['ace']['uri']))
        #alert.submit(config['ace']['uri'], config['ace']['key'])

        self.aggregate_alert(alert)

def report_exception():
    try:
        output_dir = os.path.join(BASE_DIRECTORY, 'error_reporting')
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                sys.stderr.write('unable to create directory {}: {}'.format(
                    output_dir, str(e)))
                return

        with open(os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f')), 'w') as fp:
            fp.write(traceback.format_exc())

    except Exception as e:
        logging.error("unable to report error: {}".format(str(e)))
        #traceback.print_exc()

def initialize_environment():
    global BASE_DIRECTORY
    global config

    # pre-initialize logging
    logging.basicConfig(level=logging.DEBUG)

    # load base dir from env var
    if BROTAIL_ENV_VAR in os.environ:
        BASE_DIRECTORY = os.environ[BROTAIL_ENV_VAR]
        logging.debug('loaded base directory {} from environment variable {}'.format(
            BASE_DIRECTORY, BROTAIL_ENV_VAR))

    if args is not None and args.base_directory is not None:
        BASE_DIRECTORY = args.base_directory
        logging.debug('loaded base directory {} from command line arguments'.format(BASE_DIRECTORY))

    # make sure base dir exists
    if not os.path.isdir(BASE_DIRECTORY):
        logging.fatal("invalid brotail home diretory {}".format(BASE_DIRECTORY))
        sys.exit(1)

    try:
        os.chdir(BASE_DIRECTORY)
    except Exception as e:
        logging.fatal("unable to change current directory to {}: {}".format(
            BASE_DIRECTORY, str(e)))
        sys.exit(1)

    # make sure all the directories that we need to exist actually do
    for subdir in [ 'error_reporting', 'logs', 'var' ]:
        subdir = os.path.join(BASE_DIRECTORY, subdir)
        if not os.path.isdir(subdir):
            try:
                logging.warning("creating directory {}".format(subdir))
                os.mkdir(subdir)
            except Exception as e:
                logging.fatal(str(e))
                sys.exit(1)

    # add lib/ to python path
    sys.path.append(os.path.join(BASE_DIRECTORY, 'lib'))

    # initialize logging
    try:
        logging.config.fileConfig(os.path.join(BASE_DIRECTORY, 'etc', 'brotail_logging.ini'))
    except Exception as e:
        logging.fatal("unable to initialize logging: {}".format(str(e)))

    # remove proxy settings in env
    for env_var in [ 'http_proxy', 'https_proxy' ]:
        if env_var in os.environ:
            logging.warning("removing proxy env var {}".format(env_var))
            del os.environ[env_var]

    # load configuration
    config = ConfigParser()
    try:
        config.read(os.path.join(BASE_DIRECTORY, 'etc', 'brotail.ini'))
    except Exception as e:
        logging.fatal("unable to load configuration file: {}".format(str(e)))
        sys.exit(1)

def initialize_whitelist():
    global whitelist

    # load whitelist configuration
    whitelist_config = ConfigParser()
    whitelist_path = os.path.join(BASE_DIRECTORY, 'etc', 'whitelist.ini')
    if args.whitelist_path is not None:
        whitelist_path = args.whitelist_path

    try:
        logging.debug("loading whitelist from {}".format(whitelist_path))
        whitelist_config.read(whitelist_path)
    except Exception as e:
        logging.error("unable to load whitelist from {}: {}".format(whitelist_path, str(e)))
        return

    new_whitelist = {} # key = log, value = [] of dicts(key = field_name, value = pattern)
    for name in whitelist_config.sections():
        logging.debug("loading whitelist item {}".format(name))
        if 'log_file' not in whitelist_config[name]:
            logging.error("missing required configuration value \"log\" in {}".format(name))
            continue

        bro_log = whitelist_config[name]['log_file']
        if bro_log not in new_whitelist:
            new_whitelist[bro_log] = [] # of WhitelistPattern

        patterns = {}
        for field_name in whitelist_config[name].keys():
            if field_name == 'log_file':
                continue

            logging.debug("loading field {} pattern {} for {}".format(field_name, whitelist_config[name][field_name], name))
            patterns[field_name] = whitelist_config[name][field_name]

        if len(patterns.keys()) == 0:
            logging.error("missing patterns for {}".format(name))
            continue

        new_whitelist[bro_log].append(WhitelistPattern(name, bro_log, patterns))

    whitelist = new_whitelist

def daemonize():
    # are we already running?
    daemon_pid_path = os.path.join(BASE_DIRECTORY, 'var', 'brotail.pid')
    if os.path.exists(daemon_pid_path):
        logging.error("deamon PID file {} exists: run command with -k or -K to kill existing daemon and/or delete the pid file".format(daemon_pid_path))
        sys.exit(1)

    pid = None

    # http://code.activestate.com/recipes/278731-creating-a-daemon-the-python-way/
    try:
        pid = os.fork()
    except OSError as e:
        logging.fatal("{} ({})".format(e.strerror, e.errno))
        sys.exit(1)

    if pid == 0:
        os.setsid()

        try:
            pid = os.fork()
        except OSError as e:
            logging.fatal("{} ({})".format(e.strerror, e.errno))
            sys.exit(1)

        if pid > 0:
            # write the pid to a file
            with open(daemon_pid_path, 'w') as fp:
                fp.write(str(pid))

            print("started background process {}".format(pid))
            os._exit(0)
    else:
        os._exit(0)

    import resource
    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if (maxfd == resource.RLIM_INFINITY):
        maxfd = MAXFD

        for fd in range(0, maxfd):
            try:
                os.close(fd)
            except OSError:   # ERROR, fd wasn't open to begin with (ignored)
                pass

    if (hasattr(os, "devnull")):
        REDIRECT_TO = os.devnull
    else:
        REDIRECT_TO = "/dev/null"

    os.open(REDIRECT_TO, os.O_RDWR)
    os.dup2(0, 1)
    os.dup2(0, 2)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Brotail - Bro IDS log tail to ACE alerts")
    parser.add_argument('--base-directory', default=None, dest='base_directory', 
        help="Specify a different base installation directory.")
    parser.add_argument('-w', '--whitelist', required=False, default=None, dest='whitelist_path',
        help="Alternative path to whitelist configuration.  Defaults to etc/whitelist.ini from brotail installation directory.")
    parser.add_argument('-b', '--background', required=False, default=False, action='store_true', dest='background',
        help="Fork into background and record PIDs in var subdir of installation directory.")
    parser.add_argument('-k', '--kill', required=False, default=False, action='store_true', dest='kill',
        help="Signal currently executing brotail instance to exit.")
    parser.add_argument('-K', '--super-kill', required=False, default=False, action='store_true', dest='super_kill',
        help="Kill the currently executing brotail instance.")
    parser.add_argument('-r', '--reload', required=False, default=False, action='store_true', dest='reload',
        help="Signal a reload for the running brotail instance.")

    # debugging arguments
    parser.add_argument('--debug-alerts', required=False, default=False, action='store_true', dest='debug_alerts',
        help="Send the first entry read as an Alert.")

    args = parser.parse_args()

    initialize_environment()

    if args.reload or args.kill or args.super_kill:
        # send unix signal to all the PIDs recorded in var
        for pid_file in glob.glob(os.path.join(BASE_DIRECTORY, 'var', '*.pid')):
            # the master process doesn't need to reload anything
            # and it can let child processes gracefully exit before exiting
            if ( args.reload or args.kill ) and pid_file.endswith('brotail.pid'):
                continue

            with open(pid_file, 'r') as fp:
                try:
                    pid = int(fp.read())
                except Exception as e:
                    logging.error("unable to read pid file {}: {}".format(pid_file, str(e)))
                    continue

                try:
                    if args.reload:
                        # signal to reload configuration
                        os.kill(pid, signal.SIGHUP)
                    elif args.super_kill:
                        # signal to die
                        os.kill(pid, signal.SIGKILL)
                        try:
                            os.remove(pid_file)
                        except Exception as e:
                            logging.error("unable to remove file {}: {}".format(pid_file, str(e)))
                    else:
                        # signal to gracefully exit
                        os.kill(pid, signal.SIGTERM)
                except Exception as e:
                    logging.error("unable to send signal to {}: {}".format(pid, str(e)))


        sys.exit(0)

    if args.background:
        daemonize()
    
    try:
        bro_tails = []
        for source in config['bro']['bro_sources'].split(','):
            bro_tail = Brotail(source)
            bro_tail.start()
            bro_tails.append(bro_tail)

        for bro_tail in bro_tails:
            bro_tail.wait()
        
    except KeyboardInterrupt:
        logging.warning("caught keyboard interrupt")
        try:
            for bro_tail in bro_tails:
                bro_tail.stop()

            for bro_tail in bro_tails:
                bro_tail.wait()
        except Exception as e:
            logging.error("unable to stop brotail processes: {}".format(str(e)))

    if args.background:
        try:
            os.remove(os.path.join(BASE_DIRECTORY, 'var', 'brotail.pid'))
        except Exception as e:
            logging.error("unable to remove brotail.pid: {}".format(str(e)))
