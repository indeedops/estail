# ESTAIL - An Elasticsearch cli client


## Requirements

- Python 2.6, 2.7
- Preferably pyenv

## Local Installation

```shell
pyenv virtualenv 2.6.6 estail      # create a virtualenv
pyenv activate estail
pip install -r requirements        # installed required packages to created virtualenv
alias estail='python ./estail.py'  # not strictly required, but you'll get bash completion
source ./estail_completion.sh      # get bash autocompletion
```

## Configuration

Configuration for estail can be sourced from two locations.  The first and most specific is from the users home directory $HOME/.estail.conf. A second global configuration file is sourced from /etc/estail/estail.conf  It's possible to change the name of the file that's sourced by changing the name that's passed to common.LoadElasticConfig.

### Sample Configuration
```
{
    "hosts": {"prod": "https://elastic.prod.example.com", "qa": "https://elastic.qa.example.com", "dev":"https://elastic.dev.example.com"},
    "port": 443,
    "index_date_pattern": "%Y.%m.%d",
    "application_field": "application",
    "product": ["mail","cron"],
    "timezone": "UTC"
}
```
The hosts are an object where the key is the environment and the value is the host(s) of elasticsearch. The product is an array and is the first thing that would be pivoted on when filtering through documents. It's expected that the product is a name in the index between logstash and the date.  It isn't necessary to have separate indexes becdc1e you can use filtered aliases in a single index where the product is a field in the document.

The application_field is the second pivot that's used in a term filter. It's suggested that the mapping for this field be analyzed as a keyword to prevent splitting on possible dashes.

Products are intended to be their own indexes or aliases that either point to other indexes with a filter on a field. Example: logstash-cron-2015.12.30

## Output

Two different kinds of applications are used through estail at Indeed: Java and Python. The fields are easily built using the JSONEventLayout logging libraries for those two languages: https://github.com/logstash/log4j-jsonevent-layout and https://github.com/madzak/python-json-logger. The supervisor type is used for stdout or stderr where only the message and timestamp are available.  It's simple to extend the result mapping to more types with if statements in the `_map_from_record` function.

## Autocompletion

Sourcing `estail_completion.sh` enhances estail's usability by autocompleting application names, product names, and command line switches.
Autocompletions are stored in files under `$HOME/.estail`, and are valid for 24 hours, after which they are recreated.

## Usage

```shell
usage: estail.py [-h]
                 [-p {}]
                 [-a APPLICATIONS] [-L] [-l LOOKBACK] [-r REFRESH] [-g GREP]
                 [-f] [-s STARTDATE] [-e ENDDATE] [--env {prod,qa}]
                 [-d DATACENTER] [-H HOSTNAME] [-n NUM_LOGS] [--verbose] [-P]

This script is used to tail logs out of elasticsearch. It will not follow the
logs unless -f is specified

optional arguments:
  -h, --help            show this help message and exit
  -p {}, --product {}
                        Picks the elasticsearch product instance to look in
  -a APPLICATIONS, --application APPLICATIONS
                        Application(s) to tail logs from (can be specified
                        multiple times)
  -L, --list            List all available applications, or list of
                        applications in specified the product group
  -l LOOKBACK, --lookback LOOKBACK
                        Number of seconds in the initial lookback
  -r REFRESH, --refresh REFRESH
                        How often to refresh the view (defaults to 10 seconds)
  -g GREP, --grep GREP  Search against this pattern before printing
  -f, --follow          Follow logs instead of doing a one-time tail
  -s STARTDATE, --startdate STARTDATE
                        Start date for searching between a set of dates. This
                        is the oldest date. Format: YYYY-MM-DD HH:MM
  -e ENDDATE, --enddate ENDDATE
                        End date for searching between a set of dates. This is
                        the newest date. Format: YYYY-MM-DD HH:MM
  --env {prod,qa}       Environment to search in. Defaults to prod
  -d DATACENTER, --datacenter DATACENTER
                        Filter by datacenter
  -H HOSTNAME, --hostname HOSTNAME
                        Filter by host
  -n NUM_LOGS, --logevents NUM_LOGS
                        Get number of log lines instead of logs over a time
                        period. Only works on today's date
  --verbose             Verbose mode. Prints more information
  -P, --list_products   List all product groups. Normally used for generating
                        a list file for bash auto-completion
```


## Examples

### Specify an application without specifying product
`python estail.py -a app1 -s '2014-02-06 10:30' -e '2014-02-06 11:00'`

### Specify multiple applications
`python estail.py -a app1 -a app2 -a app3`

### Specify only start time
`python estail.py -p group1 -a app1 -s '2014-02-06 10:30`

### Tail the logs continuously until stopped
`python estail.py -p group1 -a app1 -f`

### Refresh every 5 seconds
`python estail.py -p group1 -a app1 -l 1800 -r 5`

### Filter by hostname
`python estail.py -p group1 -a app1 -H host1`

### Filter by datacenter
`python estail.py -p group2 -a app5 -d dc1`

### Get last 100 log messages
`python estail.py -p group1 -a app1 -n 100`
