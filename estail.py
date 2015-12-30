#!/usr/bin/env python

# Copyright (C) 2015 Indeed Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the
# License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing permissions and
# limitations under the License.

from pyelasticsearch import ElasticSearch
from pyelasticsearch.exceptions import ElasticHttpNotFoundError
from datetime import datetime, timedelta
from dateutil import parser as dateparser
from pytz import all_timezones
import argparse
import sys
import time
import re
import os.path
import json
import pytz
import logging

# Local imports
import common

# possible products to query against
elastic_config = common.LoadElasticConfig("estail")
products = sorted(elastic_config.product)
application_field = elastic_config.application_field
index_date_pattern = elastic_config.index_date_pattern
port = elastic_config.port
timezone = elastic_config.timezone

env = "prod"
DEFAULT_RESULT_SIZE = 10000

# Setup arguments
parser = argparse.ArgumentParser(
    description="This script is used to tail logs out of elasticsearch. It will not follow the logs unless -f is specified")

parser.add_argument("-p", "--product",
                    choices=products,
                    help="Picks the elasticsearch product instance to look in",
                    action="store",
                    dest="product")

parser.add_argument("-a", "--application",
                    action="append",
                    help="Application(s) to tail logs from (can be specified multiple times)",
                    dest="applications")

parser.add_argument("-L", "--list",
                    action="store_true",
                    help="List all available applications, or list of applications in specified the product group",
                    dest="list")

parser.add_argument("-l", "--lookback",
                    action="store",
                    type=int,
                    dest="lookback",
                    default=60,
                    help="Number of seconds in the initial lookback")

parser.add_argument("-r", "--refresh",
                    type=int,
                    action="store",
                    dest="refresh",
                    default=10,
                    help="How often to refresh the view (defaults to 10 seconds)")

parser.add_argument('-m', '--match-regex',
                    action="store",
                    dest="match",
                    help="Search against this pattern before printing. Uses python regex")

parser.add_argument('-f', '--follow',
                    action="store_const",
                    const=True,
                    dest="follow",
                    help="Follow logs instead of doing a one-time tail")

parser.add_argument('-s', '--startdate',
                    action="store",
                    dest="startdate",
                    help="Start date for searching between a set of dates. This is the oldest date. Format: YYYY-MM-DD HH:MM")

parser.add_argument('-e', '--enddate',
                    action="store",
                    dest="enddate",
                    help="End date for searching between a set of dates. This is the newest date. Format: YYYY-MM-DD HH:MM")

parser.add_argument('--env',
                    action="store",
                    dest="env",
                    default="prod",
                    choices=elastic_config.envs,
                    help="Environment to search in. Defaults to prod")

parser.add_argument('-d', '--datacenter',
                    action="store",
                    dest="datacenter",
                    help="Filter by datacenter")

parser.add_argument('-H', '--hostname',
                    action="store",
                    dest="hostname",
                    help="Filter by host")

parser.add_argument('-n', '--logevents',
                    action="store",
                    dest="num_logs",
                    type=int,
                    help="Get number of log lines instead of logs over a time period.  Only works on today's date")

parser.add_argument('--verbose',
                    action="store_const",
                    const=True,
                    dest="verbose",
                    help="Verbose mode.  Prints more information"
                    )

parser.add_argument('-P', '--list_products',
                    action="store_true",
                    dest="list_products",
                    help="List all product groups. Normally used for generating a list file for bash auto-completion"
                    )

class LogQueryBuilder:
    def __init__(self):
        self.applications = []
        self.datacenter = None
        self.hostname = None
        self.range_from = None
        self.range_to = None
        self.result_size = None

    def add_application(self, app_name):
        self.applications.append(app_name)

    def set_datacenter(self, datacenter):
        self.datacenter = datacenter

    def set_hostname(self, hostname):
        self.hostname = hostname

    def set_range_from(self, from_time):
        self.range_from = from_time

    def set_range_to(self, to_time):
        self.range_to = to_time

    def set_size(self, result_size):
        self.result_size = result_size

    def build_query(self):
        query = dict()
        query["_source"] = ["@timestamp",
                            "exception",
                            "message",
                            "class",
                            "filename",
                            "level",
                            "levelname",
                            "host",
                            "thread_name",
                           ]
        query["filter"] = {"bool": { "must": [], "should": [] } }
        for application in self.applications:
            query["filter"]["bool"]["should"].append({"term": {application_field: application}})
        if self.datacenter is not None:
            query["filter"]["bool"]["must"].append({"term": {"datacenter": self.datacenter}})
        if self.hostname is not None:
            query["filter"]["bool"]["must"].append({"term": {"host": self.hostname}})
        if self.result_size is None:
            # result_size is not specified.
            query["size"] = DEFAULT_RESULT_SIZE
            query["sort"] = [{"@timestamp": {"order": "asc"}}]
            if self.range_from is not None or self.range_to is not None:
                range_filter = {"@timestamp": {}}
                if self.range_from is not None:
                    range_filter["@timestamp"]["from"] = self.range_from
                if self.range_to is not None:
                    range_filter["@timestamp"]["to"] = self.range_to
                query["filter"]["bool"]["must"].append({"range": range_filter})
        else:
            # result_size is specified. therefore we do not use range filter.
            query["size"] = self.result_size
            query["sort"] = [{"@timestamp": {"order": "desc"}}]
        query["from"] = 0
        return query

# query to get log entries
APPLICATIONS_QUERY = {
    "_source": [application_field],
    "facets": {
        "applications": {
            "terms": {
                "field": application_field,
                "size": 1000
                }
            }
        }
    }

DOT_ESTAIL = "%s/.estail" % os.environ['HOME']
APPLICATION_LIST_CACHE = "%s/applications" % DOT_ESTAIL
APPLICATION_PROD_MAP_CACHE = "%s/application_prods.json" % DOT_ESTAIL
MAX_CACHE_AGE_SEC = 86400

def _index_prefix_for_product(product_group):
    return 'logstash-{0}-%(date)s'.format(product_group)

def _indices_for_product(product_group):
    index_prefix = _index_prefix_for_product(product_group)
    today = index_prefix % {'date': datetime.utcnow().strftime(index_date_pattern)}
    yesterday = index_prefix % {
        'date': (datetime.utcnow() - timedelta(days=1)).strftime(index_date_pattern)}

    return today, yesterday

def _query_applications(product_group, indices):
    hosts = [_url_for_host(env)]

    es = ElasticSearch(hosts, port = port)
    es_results = es.search(APPLICATIONS_QUERY, index=indices)

    applications = map((lambda result: result['term']), es_results['facets']['applications']['terms'])
    return applications

def _query_all_applications():
    all_indices = []
    for product_group in products:
        today, yesterday = _indices_for_product(product_group)
        all_indices.extend([today, yesterday])
    return _query_applications(product_group, all_indices)

# create the file specied by path if it doesn't exist or is older than one day
def _create_cache_file(path, query_func, store_func):
    if not os.path.exists(DOT_ESTAIL):
        os.makedirs(DOT_ESTAIL)

    def _query_and_save():
        query_res = query_func()
        with open (path, "w") as f:
            store_func(query_res, f)

    if not os.path.isfile(path):
        _query_and_save()
    else:
        # recreate file if older than one day
        mtime_sec = os.path.getmtime(path)
        now_sec = time.time()
        if (now_sec - MAX_CACHE_AGE_SEC) > mtime_sec:
            _query_and_save()

def _query_product_for_app(app):
    logging.info("Searching for product group matching application '%s'\n" % app)

    def _query():
        res = {}
        for product_group in products:
            today, yesterday = _indices_for_product(product_group)
            applications = _query_applications(product_group, [today, yesterday])
            for app in applications:
                res[app] = product_group
        return res

    def _store(query_res, f):
        json.dump(query_res, f)

    _create_cache_file(APPLICATION_PROD_MAP_CACHE, _query, _store)

    with open (APPLICATION_PROD_MAP_CACHE, "r") as f:
        app_product_map = json.load(f)

    if app in app_product_map:
        res = app_product_map[app]
        logging.info("Found matching product group: '%s'\n" % res)
        return res

    # no product matched
    return None

def _list_applications(args):
    """
    Prints out a list of applications that are in a elasticsearch product group
    """
    product_group = args.product
    print "available applications for product group '%s':" % product_group
    today, yesterday = _indices_for_product(product_group)
    applications = _query_applications(product_group, [today, yesterday])
    sorted_applications = sorted(applications)
    for app in sorted_applications:
        print app

def _query_available_indices(es):
    aliases = es.aliases()
    res = set()
    for key in aliases:
        if 'aliases' in aliases[key]:
            sub_aliases = aliases[key]['aliases']
            for sub_alias in sub_aliases:
                res.add(sub_alias)

    indexes = es.get_settings('logstash-*').keys()
    for index in indexes:
        res.add(index)

    return res

def _parse_date_string(date_string):
    """
    Convert datetime object fron given string which represents the date.

    If timezone is not specified in the input,
    the timezone is taken from configuration. If not specified timezone is
    taken from configuration.  Default timezone is UTC
    :param date_string:
    :return datetime object:
    """
    result = dateparser.parse(date_string)
    if result.tzinfo is None:
        result = pytz.timezone(timezone).localize(result)
    return result


def _get_indexes(product_group, start_datetime, end_datetime, es):
    """
    Pass a start and end date and get a list of logstash indexes
    """
    index_list = set()

    normalized_start = start_datetime.astimezone(pytz.utc).replace(hour=0, minute=0, microsecond=0)
    normalized_end = end_datetime.astimezone(pytz.utc).replace(hour=0, minute=0, microsecond=0)
    delta = timedelta(days=1)
    date_cursor = normalized_start
    index_prefix = _index_prefix_for_product(product_group)
    while True:
        index_list.add(index_prefix % {'date': date_cursor.strftime(index_date_pattern)})
        date_cursor = date_cursor + delta
        if date_cursor > normalized_end:
            break

    available_indices = _query_available_indices(es)

    difference = index_list.difference(available_indices)
    if len(difference) > 0:
        logging.info("indices %s not found in Elastic search (perhaps future or distant past) and will not be queried\n" % str(difference))

    return list(index_list.intersection(available_indices))

def _map_from_record(result, applications):
    res = {}
    _source = result['_source']
    try:
        res['timestamp'] = _source['@timestamp']
        res['message'] = _source['message']
        res['host'] = _source['host']
        if ('_type' in result) and (result['_type'] == "supervisor"):
            res['class_name'] = ''
            res['level'] = ''
            res['thread_name'] = ''
        elif ('_type' in result) and (result['_type'] == "python"):
            res['class_name'] = _source['filename']
            res['level'] = _source['levelname']
            res['thread_name'] = ''

            # did the dev's give us a stacktrace?
            if 'exception' in _source:
                res['exception'] = u"\n{0}".format("".join(_source['exception']))
        else:
            res['class_name'] = _source['class']
            res['level'] = _source['level']
            if 'thread_name' in _source:
                res['thread_name'] = "[{0}]".format(_source['thread_name'])
            else:
                res['thread_name'] = ''

            # did the dev's give us a stacktrace?
            if 'exception' in _source:
                res['exception'] = u"\n{0} {1}".format(_source['exception']['exception_class'], _source['exception']['stacktrace'])
    except KeyError as ke:
        if ke:
            logging.info(
                "{0} Bad Log for application(s) {1} on field {2}\n".format(datetime.now(), applications, ke[0]))
        return None

    return res

def _check_es_health(product, env):
    if product is not None:
        hosts = [_url_for_host(env)]
    else:
        logging.info("No product specified ; Checking health of all Elasticsearch hosts for env '%s'\n" % env)
        all_hosts = set(product_host.values())
        hosts = []
        for host in all_hosts:
            hosts.append(_url_for_host(env, host))

    es = ElasticSearch(hosts, port = port)

    # Add check on elasticsearch health
    health = es.health()

    if health['status'] == 'red':
        logging.error("Elasticsearch status is red. Search will hang. Exiting\n")
        sys.exit(-1)
    elif health['status'] == 'yellow':
        logging.warning('Elasticsearch status is yellow. Search quality will be degraded\n')

def _url_for_host(env):
    logging.info("Pulled host {0} from config".format(elastic_config.hosts[env]))
    return elastic_config.hosts[env]

def _remove_missing_indices(indices, err):
    for idx in indices:
        if idx in err:
            logging.info("Matched missing index '%s' in error message '%s' ; will remove it from index list\n" % (idx, err))
            indices.remove(idx)
    return indices

def _list_products():
    for i in products:
        print i


def _list_all_applications(args):
    def _store(query_res, f):
        for app in sorted(query_res):
            f.write("%s\n" % app)

    _create_cache_file(APPLICATION_LIST_CACHE, _query_all_applications, _store)

    with open (APPLICATION_LIST_CACHE, "r") as apps_file:
        lines = apps_file.read().split("\n")
        for line in lines:
            print line


def extract_product(args):
    # if there is no product
    found_products = set()
    for application in args.applications:
        product = _query_product_for_app(application)
        if product is not None:
            found_products.add(product)
            if len(found_products) > 1:
                logging.error("Found more than 1 matching product groups for the specified applications: %s" % str(found_products))
                logging.error("Please specify applications from only one product group")
                parser.print_help()
                sys.exit(1)
        else:
            # product could not be matched
            logging.error("No application matching '%s' was found" % application)
            logging.error("Possible applications are: ")
            _list_all_applications(args)
            parser.print_help()
            sys.exit(1)
    return list(found_products)[0]

def get_builder_from_args(args):
    query_builder = LogQueryBuilder()

    # set timerange.
    if not args.startdate:
        logging.info('start date is not specified. use lookback option.')
        to_stamp = datetime.now(pytz.utc)
        from_stamp = to_stamp - timedelta(seconds=args.lookback)
    else:
        from_stamp = _parse_date_string(args.startdate)
        if not args.enddate:
            logging.info('start date is specified, but end date is not. set end date as now + 6h.')
            to_stamp = datetime.now(pytz.timezone(timezone)).replace(second=0, microsecond=0) + timedelta(hours=6)
        else:
            to_stamp = _parse_date_string(args.enddate)
        logging.info('both start and end date is specified. Pagination enabled.')
    logging.info('Time range is set as follows. start:{0} - end:{1}'.format(from_stamp, to_stamp))
    query_builder.set_range_from(from_stamp)
    query_builder.set_range_to(to_stamp)

    # set filters.
    for application in args.applications:
        logging.info('application: {0}'.format(application))
        query_builder.add_application(application)
    if args.datacenter:
        logging.info('datacenter: {0}'.format(args.datacenter))
        query_builder.set_datacenter(args.datacenter)
    if args.hostname:
        logging.info('hostname: {0}'.format(args.hostname))
        query_builder.set_hostname(args.hostname)
    if args.num_logs:
        logging.info('num_logs: {0}'.format(args.num_logs))
        query_builder.set_size(args.num_logs)
    return query_builder


def query_main(args):
    _check_es_health(args.product, env)

    # make sure product is set.
    if not args.product:
        logging.info('No products is specified. Extract it from specified applications.')
        product = extract_product(args)
    else:
        product = args.product
    assert product, 'No product is specified. This is weird.'
    logging.info('Product group: {0}'.format(product))

    # create ElasticSearch client.
    hosts = [_url_for_host(env)]
    es = ElasticSearch(hosts, port=port)

    # build query
    query_builder = get_builder_from_args(args)
    paginated = bool(args.startdate)

    # calculate search index from timerange.
    search_index = _get_indexes(product, query_builder.range_from, query_builder.range_to, es)
    if len(search_index) == 0:
        logging.error('There is no index to search in.')
        exit(1)

    if args.match:
        pattern = re.compile(args.match)

    logging.info('Index to search in {0}'.format(search_index))
    while True:
        # query
        results = es.search(query_builder.build_query(), index=search_index)
        hit_count = results['hits']['total']
        logging.info('Found: {0} logs.'.format(hit_count))

        # are there any results?
        if hit_count == 0:
            if not paginated:
                logging.info(
                    "{0} No Results for application(s): {1}\n".format(datetime.now(), args.applications))
            if not args.follow:
                break

        if args.num_logs:
            # Logs are in reverse order. Re-sort them
            results['hits']['hits'] = sorted(
                results['hits']['hits'], key=lambda x: x['_source']['@timestamp'])

        # yeah there's results, print em out!
        for result in results['hits']['hits']:
            res_map = _map_from_record(result, args.applications)
            if res_map is None:
                continue

            message = u"{0} {1} {2} [{3}] {4} {5}".format(
                res_map['timestamp'], res_map['host'], res_map['level'], res_map['class_name'], res_map['thread_name'], res_map['message']).encode('utf-8')
            if 'exception' in res_map:
                # better hand this exception stuff over
                message += res_map['exception'].encode('utf-8')
            # we wanna use a regex
            if args.match:
                if pattern.search(message):
                    print message
            else:
                print message

        # stop looping if we're not following
        if paginated:
            query_builder.set_range_from(_parse_date_string(result['_source']['@timestamp']) + timedelta(microseconds=1000))
        elif not args.follow or args.num_logs:
            break

        if results['hits']['total'] == 0 and not paginated:
            time.sleep(args.refresh)
        elif not paginated:
            query_builder.set_range_from(_parse_date_string(result['_source']['@timestamp']) + timedelta(microseconds=1000))


def main(args):
    # set global state. env and verbose.
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.ERROR)
    global env
    env = args.env
    if not timezone in all_timezones:
        logging.error('timezone {0} is not available through pytz'.format(timezone))
        sys.exit(-1)

    if args.list_products:
        _list_products()
        exit(0)
    elif args.list:
        if args.product and len(args.product) > 0:
            _list_applications(args)
        else:
            _list_all_applications(args)
        exit(0)
    elif args.applications:
        query_main(args)
    elif args.product:
        logging.error('please specify application.')
        logging.error('available applications are:')
        _list_applications(args)
        exit(1)
    else:
        logging.error('No action command is specified. abort.')
        parser.print_help()
        exit(1)

if __name__ == '__main__':
    main(parser.parse_args())
