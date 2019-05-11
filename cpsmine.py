#!/usr/bin/env python3
'''Script to estimate flood protection values.

Based on the python2 version by Glenn Hårseide.

Modified for python3 by David Couture.
'''


from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, SUPPRESS
import csv
from datetime import datetime, timedelta
import statistics
import sys


FMT = "%Y/%m/%d %H:%M:%S"
COMPRESS_FMT = "%Y%m%d%H%M%S"

PROTO_LIST = ('icmp', 'tcp', 'udp')


def add_group_args(group):
    '''add_group_args

    Add mutually exclusive arguments.

    '''

    group.add_argument(
        '-i', '--interface',
        default=SUPPRESS,
        help='Interface for which cps needs to be calculated.')

    group.add_argument(
        '-z', '--zone',
        default=SUPPRESS,
        help='Ingress Zone for which cps needs to be calculated.')


def add_optional_args(parser):
    '''add_optional_args

    Add optional arguments.

    '''

    parser.add_argument(
        '-f', '--filename',
        default='log.csv',
        help='File name including the full path if not residing '
        'in the script dir.')

    parser.add_argument(
        '-c', '--highcps',
        type=int,
        default='10000',
        help='Maximum cps value for an interval to be considered. '
        'Anything higher will be ignored for threshold calculation.')

    parser.add_argument(
        '-t', '--interval',
        type=int,
        default='1',
        help='Polling interval to collect statistics.')

    parser.add_argument(
        '-l', '--lowcps',
        type=int,
        default='1',
        help='Minimum cps value for an interval to be considered. '
        'Anything lower will be ignored for threshold calculation.')

    parser.add_argument(
        '-p', '--protocol',
        choices=(PROTO_LIST + ('other', 'all')),
        default='all',
        help='Protocol for which cps needs to be calculated. '
        'By default we calculate cps for udp/tcp and icmp.')

    parser.add_argument(
        '-s', '--suppress',
        choices=('true', 'false'),
        default='true',
        help='Suppress logging for every epoch interval.')


def cli_parseargs():
    '''cli_parseargs'''

    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description='Script to extract cps information for the firewall.')

    # Add the optional arguments.

    add_optional_args(parser)

    # Add the group of mutually exclusive arguments.

    group = parser.add_mutually_exclusive_group(required=True)
    add_group_args(group)

    return parser.parse_args()


def evaluate_cpsdict(cpsdict, cli_vars):
    '''evaluate_cpsdict

    Loop over the count per second dictionary looking for
    timestamps|counts that should be added to count per second list.

    '''
    if not cpsdict:
        return

    # Use interval as a timedelta for easy comparison.

    interval = timedelta(seconds=cli_vars['interval'])

    sorted_keys = sorted(cpsdict)

    # Set initial values using the first sorted key.

    previous_key = sorted_keys[0]
    previous_ts = datetime.strptime(previous_key, COMPRESS_FMT)

    count = cpsdict[previous_key]

    cpslist = []

    # Loop over the remaining sorted keys starting from the second key.

    for key in sorted_keys[1:]:

        ts = datetime.strptime(key, COMPRESS_FMT)

        # Check if the time delta between the two timestamps
        # is smaller than 1/2 of the interval.

        if (ts - previous_ts) <= interval/2:
            count += 1
            continue

        # Check if this row should be added to cpslist.

        evaluate_row(cpslist, count, previous_ts, cli_vars)

        # Reset values for the next iteration.

        previous_key = key
        previous_ts = ts
        count = cpsdict[key]

    # There may be an active count that didn't get evaluated
    # before EOF so call evaluate_row() just to be sure.

    evaluate_row(cpslist, count, previous_ts, cli_vars)

    return cpslist


def evaluate_row(cpslist, count, ts, cli_vars):
    '''evaluate_row

    Determine if row should be added to cpslist.

    '''
    if ts is None:
        return

    highcps = cli_vars['highcps']
    interval = cli_vars['interval']
    lowcps = cli_vars['lowcps']
    suppress = (cli_vars['suppress'] == 'true')

    highlight = ''

    cps = count/interval

    if count > 1:
        if cps > lowcps and cps < highcps:

            # Add entry to cpslist array and set the highlight for
            # when it's printed.

            cpslist.append(cps)
            highlight = '** '

    if not suppress:
        print(f'{highlight}{ts} cps is {cps}')


def main():
    '''main'''

    cli_args = cli_parseargs()
    cli_vars = vars(cli_args)

    # Set mutually exclusive values.

    cli_vars['interface'] = cli_vars.get('interface')
    cli_vars['zone'] = cli_vars.get('zone')

    fname = cli_vars['filename']

    try:
        with open(fname, newline='') as csvfile:
            reader = csv.DictReader(csvfile)

            cpsdict = process_csvfile(reader, cli_vars)

            cpslist = evaluate_cpsdict(cpsdict, cli_vars)

            print_results(cpslist, cli_vars)

    except UnicodeDecodeError as errmsg:
        sys.exit('ERROR: file: {}, line: {}; {}'.format(
            fname, reader.line_num, errmsg))
    except FileNotFoundError as errmsg:
        sys.exit(errmsg)
    except PermissionError as errmsg:
        sys.exit(errmsg)


def print_results(cpslist, cli_vars):
    '''print_results'''

    if not cpslist:
        return

    interface = cli_vars['interface']
    proto = cli_vars['protocol']
    zone = cli_vars['zone']

    # Print banners and stats.

    if cpslist:

        # Determine which header to use.

        if zone:
            header = f'zone={zone}'
        else:
            header = f'interface={interface}'

        print(f'CPS Stats for {header} and protocol={proto}')
        print_stats(cpslist, header)


def print_stats(cpslist, header):
    '''print_stats

    Calculate the statistics from the values in count per second list
    and print them followed by the recommended thresholds.

    '''
    if not cpslist:
        return

    # Need at least 2 data points to calculate stdev.

    if len(cpslist) == 1:
        sys.exit('ERROR: Need a least two data points to calculate '
                 'standard deviation.')

    mean = statistics.mean(cpslist)
    stdev = statistics.stdev(cpslist)

    print(f'Max cps for {header} is= {max(cpslist):.0f}')
    print(f'Avg cps for {header} is= {mean:.3f}\n')
    print(f'Standard Deviation for {header} is= {stdev:.3f}\n')

    print_thresholds(max(cpslist), mean, stdev)


def print_thresholds(peak, mean, stdev):
    '''print_thresholds

    Print suggested threshold values.

    '''
    print('********** Suggested Threshold Values **********')

    print(f'Alert Threshold = {mean+stdev:.3f}')
    print(f'Activate Threshold = {1.1 * peak:.3f}')
    print(f'Max Threshold = {1.1 * 1.1 * peak:.3f}')


def process_csvfile(reader, cli_vars):
    '''process_csvfile

    Loop over the whole CVS file a filter out matching lines and add
    those the the count per second dictionary (cpsdict).

    '''
    START_TIME = 'Start Time'

    # Required values either set by user or by defaults.

    fname = cli_vars['filename']
    interface = cli_vars['interface']
    interval = cli_vars['interval']
    proto = cli_vars['protocol']
    zone = cli_vars['zone']

    cpsdict = {}

    try:

        for row in reader:

            if skip_row(row, interface, proto, zone):
                continue

            t1 = datetime.strptime(row[START_TIME], FMT)

            compress_t1 = t1.strftime(COMPRESS_FMT)

            # If there is already an key for compress_t1 then add one
            # to its count otherwise create a new key entry.

            if cpsdict.get(compress_t1):
                cpsdict[compress_t1] += 1
            else:
                cpsdict[compress_t1] = 1

    except csv.Error as errmsg:
        sys.exit('ERROR: file: {}, line: {}; {}'.format(
            fname, reader.line_num, errmsg))

    return cpsdict


def skip_row(row, interface, proto, zone):
    '''skip_row

    Returns True if row should be skipped.

    Returns False if row should NOT be skipped.

    '''

    IP_PROTO = 'IP Protocol'

    # Set row_key and target depending on whether we are searching for
    # an interface or a zone.

    if interface:
        row_key = 'Inbound Interface'
        target = interface
    else:
        row_key = 'Source Zone'
        target = zone

    # Don't even look at the proto if the target doesn't match.

    if row[row_key] != target:
        return True

    if proto == 'all':
        return False

    if proto == 'other' and row[IP_PROTO] not in PROTO_LIST:
        return False

    if proto == row[IP_PROTO]:
        return False

    return True


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
