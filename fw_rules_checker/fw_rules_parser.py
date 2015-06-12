#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import urllib2
import pprint
import argparse

__author__ = 'pioo'
__version__ = '0.09.02a'


class FwRule(object):
    """firewall rule object
    """

    def __init__(self, raw_rule, sources, targets, comment, is_checkable):
        """
        :param raw_rule: rule parsed into 1 line
        :return:
        """
        self.raw_rule = raw_rule

        self.sources = sources
        self.targets = targets

        self.comment = comment
        # TODO rule hash a comment alapjan
        # hogy kozpontilag kezelheto legyen a szkenneles eredmenye
        self.rule_hash = False

        self.is_checkable = is_checkable

        self.result = []
        self.is_working = False

    def addresult(self, result):
        self.result = result



class RuleParser(object):
    """parser object
    it parses the file, creates the rule from multiple lines and check the rule
    * FwRule contains the parsed and checked rules
    """

    def __init__(self, rules, invalid_rules):
        self.line = ''
        self.raw_rule = ''
        self.rules = rules
        self.invalid_rules = invalid_rules


    def addline(self, line, rules, invalid_rules, definitions):
        """
        itt a fajl tobb sorabol rakunk ossze egy kerek rule-t
        minimali szintaktikai ellenorzes tortenik
        :param line:
        :param rules:
        :param invalid_rules:
        :param definitions:
        :return:
        """
        if line.startswith('[') and self.raw_rule:
            # ha uj rule-t kezdunk, a regit commitoljuk, ha van
            if self.raw_rule.count('=>') == 1:
                # a rule szintaktika ellenorzese
                (a, b, c, d, e) = self.split_raw_rule()
                #print(a, b, c, d, e)
                new_rule = FwRule(a, b, c, d, e)
                if self.is_valid(new_rule):
                    self.rules.append(new_rule)
                else:
                    self.invalid_rules.append(self.raw_rule)
            else:
                self.invalid_rules.append(self.raw_rule)
            self.raw_rule = line
            return
        # uj definiciot kezdunk
        if line.startswith('define '):
            # here comes a new definition
            [k, v] = line.strip('define').replace(' ', '').split('=')
            k, v = k.strip(), v.strip()
            definitions[k] = []
            if 'http://' in v:
                for line2 in urllib2.urlopen(v).read().splitlines():
                    line2 = line2.strip()
                    if line2 and not line2.startswith('#'):
                        definitions[k].append(line2)
            else:
                definitions[k] = v.replace('\'', '').replace(']', '').split(',')
            return

        if line and not line.startswith('#') and not line.isspace():
            self.raw_rule += line
        return

    def split_raw_rule(self):
        sources = {}
        targets = {}
        is_checkable = False
        raw_rule, temp, comment = self.raw_rule.partition('#')
        del temp

        # a => jel bal oldalanak feldolgozasa (self.sources)
        for source in raw_rule.split('=>')[0].replace(' ', '').split('],['):
            source = source.replace('[', '').replace(']', '').replace(' ', '')
            if source.count(':'):
                # van portszam a forrasmeghatarozasban
                [sourcename, sourceports] = source.split(':')
            else:
                # nincs portszam a forrasmeghatarozasban
                sourcename = source
                sourceports = '*'
            sources[sourcename] = []
            sources[sourcename].append(sourceports.split(','))
        # a => jel jobb oldalanak feldolgozasa (self.targets)
        for target in raw_rule.split('=>')[1].replace(' ', '').split('],['):
            target = target.replace('[', '').replace(']', '').replace(' ', '')
            if ':' in target:
                # van portszam a target-ben
                [targetname, targetports] = target.split(':')
                targetname, targetports = targetname.strip(), targetports.strip()

                portlist = []
                for port in targetports.split(','):
                    if '-' in port:
                        # a port from-to range-kent van megadva
                        [startport, endport] = port.split('-')
                        portlist += map(str, range(int(startport), int(endport) + 1))
                    else:
                        portlist.append(port)

                if ('*' in targetname and targetname in definitions) or targetname in definitions:
                    # fel kell oldani egy definition-t a target neveben
                    for v in definitions[targetname]:
                        targets[v] = portlist
                else:
                    # nincs definicio a target neveben
                    targets[targetname] = portlist
            else:
                # nincs portszam a targetben
                # TODO erre a szalra nem szabad futni sosem
                print('PARSE ERROR: %s' % comment)
                targetname = target.strip()
                if '*' in targetname:
                    # feloldani a definitiont
                    for v in definitions[targetname]:
                        targets[v] = []
                else:
                    #self.targets.append([targetname, '*'])
                    targets[targetname] = []
                return False, False, comment, False
        # TODO szemantikai ellenorzes
        for k in sources:
            if k == myclass or k.replace('*', '') in myhostname:
                is_checkable = True

        return raw_rule, sources, targets, comment, is_checkable

    def is_valid(self, rule):
        """
        rule szemantikai ellenorzese
        egy szintaktikaliag helyes rule tartalmazhat szemantikai hibakat
        :return:
        """
        # celmeghatarozasban (hostnev, port) sehol nem maradhat *
        for target,ports in rule.targets.items():
            if target.count('*') != 0:
                # a hostnevben van *
                return False
            for port in ports:
                if port.count('*') != 0:
                    # a portmeghatarozasban van *
                    return False
                break
        return True


def check_tcp_port(target, port):
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect((target, int(port)))
        s.close()
        return True
    except socket.error:
        s.close()
        return False


def addresult(host, port, result):
    """this function builds the result dataset scan_result
    host: IP address
    port: port number
    result: result of portscan (bool)
    """
    # scan_result_by_state = {}
    if not host in scan_result_by_port:
        scan_result_by_port[host] = {}
    scan_result_by_port[host][port] = result

    # vagy
    if not host in scan_result_by_state:
        scan_result_by_state[host] = {'open': [], 'close': []}
    if not scan_result_by_state[host]['open'].count(port) and \
            not scan_result_by_state[host]['close'].count(port):
        if result:
            scan_result_by_state[host]['open'].append(port)
        else:
            scan_result_by_state[host]['close'].append(port)


def check_udp_port(target, port):
    msg = 'PING'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(msg, (target, int(port)))
        # s.close()
        ret = s.recv(1)
        print('UDP answer: %s' % (ret, ))
        return True
    except socket.error, msg:
        print msg
        s.close()
        return False


def print_definitions(definitions):
    print('definitions:')
    for k, v in definitions.items():
        print('%s: %s' % (k, v))


def print_parsed_rule(rule):
    print('RULE: %s' % rule.raw_rule)
    print('    Leiras: %s' % rule.comment)
    for source in rule.sources:
        print('    src: %s, ports: %s' % (source, rule.sources[source]))
    for target in rule.targets:
        print('    dst: %s, ports: %s' % (target, rule.targets[target]))
    print


def check_taget_ports(host, ports):
    elerheto = []
    blokkolt = []
    message = ''
    status = True
    for port in ports:
        if port.startswith('U'):
            # udp ellenorzes
            # check_udp_port(check_host, check_port.strip('U'))
            #message += '[D] PORT: %s [SKIPPED] (notimplemented)' % (port, ) + "\n"
            pass
        else:
            if check_tcp_port(host, port):
                elerheto.append(port)
                addresult(host, port, True)

            else:
                blokkolt.append(port)
                addresult(host, port, False)
    if len(blokkolt) > 0:
        message = '[W] %s eseten zart portba utkoztunk: ' % host
        message += 'TCP [BLOKKOLT] %s' % (blokkolt, ) + "\n"
        status = False
    return status, message


def check_rule(rule, definitions):
    """
    a rule altal leirt port elerhetoseget ellenorzi
    :param rule: rule object
    :param definitions: definitions dictionary
    :return: Bool status, String report
    """
    message = ''
    status = True

    if rule.is_checkable:
        message += '-' * 27 + 'Tuzfalkerelem informacio' + '-' * 27 + "\n"
        message += '[I] Forras: %s' % (rule.sources, ) + "\n"
        message += '[I] Cel: %s' % (rule.targets, ) + "\n"
        message += '[I] Megjegyzes: %s' % (rule.comment, ) + "\n"
        for host, ports in rule.targets.items():
            # message = ''
            #print target
            if host in definitions:
                # TODO ez itt felesleges, korabban mar ki lettek bontva a classok
                print("\n\n\t\t BUG FOUND!!!!!\n\t\tUNPARSED DEFINITION\n\n")
                for v in definitions[host]:
                    temp1, temp2 = check_taget_ports(v, ports)
                    if not temp1:
                        status = False
                    message += temp2
            else:
                temp1, temp2 = check_taget_ports(host, ports)
                message += temp2
                if not temp1:
                    status = False
        rule.is_working = status
        rule.result = 'szom'
    return status, message


def parse_args():
    """
    Argument parsing as usual.
    Hence this is a command line application this def is the
    interface.
    """
    description = "Firewall Rule Enablement Checker"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--version', action="version", version=__version__)

    mode_group = parser.add_argument_group('Working mode')
    mode_group.add_argument('-m', '--mode',
                            dest="mode_desc",
                            const='report',
                            default='report',
                            choices=['report', 'nagios', 'html', 'raw', 'diag'],
                            metavar="mode",
                            nargs="?",
                            help="Output mode, can be report, nagios, html, raw")

    options_group = parser.add_argument_group('Other options')
    options_group.add_argument('-w', '--warning',
                               dest="warning",
                               metavar='warning_count',
                               help="Nagios mode: warning count")
    options_group.add_argument('-c', '--critical',
                               dest="critical",
                               metavar="critical_count",
                               help="Nagios mode: critical count")
    options_group.add_argument('-v', '--verbose',
                               action='store_true',
                               help="Report mode: print more verbose report")
    options_group.add_argument('-o', '--order',
                               dest="raw_order",
                               const='byport',
                               default='byport',
                               choices=['byport', 'bystate', 'old1', 'old2'],
                               metavar="raw_order",
                               nargs="?",
                               help="RAW mode: ordering")
    options_group.add_argument('-d', '--diag',
                               action='store_true',
                               help="Show diag data at the end of")
    options_group.add_argument('--class',
                               dest="srcclass",
                               const='Kozp',
                               default='Kozp',
                               choices=['Kozp', 'Telep', 'Vegek', 'Internet'],
                               metavar="srcclass",
                               nargs="?",
                               help="Source class of check location")
    options_group.add_argument('-u', '--url',
                               dest="ruleurl",
                               metavar="ruleurl",
                               default='http://myserver.local/configuration/fw_rules/fw_rules.txt',
                               help="FW rules url")

    return parser, parser.parse_args()


myhostname = socket.gethostname()
myipaddress = socket.gethostbyname_ex(myhostname)[2]

scan_result_by_port = {}
scan_result_by_state = {}


def main():
    # parancssori opciok kiolvasasa
    parser, args = parse_args()

    # a tuzfalszabalyok eleresi utvonala
    rules_url = args.ruleurl

    global myclass
    myclass = args.srcclass

    # ebben a tombben taroljuk el az FwRule objektumokat
    rules = []

    # ebben a tombben taroljuk el a feldolgozhatatlan szabalyokat
    invalid_rules = []

    # ez az osztaly fogja feldolgozni a tuzfalszabalyokat
    parser = RuleParser(rules, invalid_rules)

    # ebben a dictionary-ban taroljuk el a tuzfalszabalyok ertelmezesehez fontos metaadatokat
    # TODO a definitions ne legyen global
    global definitions
    definitions = {}

    # letoltjuk a szabalyokat a fent megnevezett url-rol
    rules_data = urllib2.urlopen(rules_url).read().splitlines()
    for line in rules_data:
        parser.addline(line.strip(), rules, invalid_rules, definitions)

    # print args
    if args.mode_desc == 'report':
        # feltoltott szabalyok es definitionok
        print('[I] Using rules file: %s' % (rules_url,))
        print('[D] Valid/invalid rules count: %s/%s, definitions count: %s' % (
            len(rules), len(invalid_rules), len(definitions)))
        print('[I] My hostname: %s, IP address: %s, "Class": %s' % (
            myhostname, myipaddress, myclass))
        #print_definitions(definitions)
        #pprint.pprint(invalid_rules)
        print
        for rule in rules:
            if rule.is_checkable:
                status, report1 = check_rule(rule, definitions)
                if not status:
                    print('[FAIL] %s' % rule.raw_rule)
                    print report1
                else:
                    print('[OK] %s' % rule.raw_rule)

    elif args.mode_desc == 'nagios':
        # TODO args.warning es args.critical ellenorzese
        nagios_ok = True
        message = ''
        message_details = 'CLOSED PORTS: '
        for rule in rules:
            if rule.is_checkable:
                status, report1 = check_rule(rule, definitions)
                if not status:
                    nagios_ok = False
                    message += ' FAILED RULE "%s"' % rule.comment
        if nagios_ok:
            print('OK')
            exit(0)
        else:
            for k, v in scan_result_by_state.items():
                if len(v['close']):
                    message_details += k + ':' + str(v['close'])
            print('WARNING: %s (%s)' % (message, message_details))
            exit(1)
        pass
    elif args.mode_desc == 'html':
        # TODO felve kerdezem, template?
        print('<HTML><BODY>')
        print('<H2>HOSTNAME: %s</H2><br>' % (myhostname, ))
        print('<p>[I] Using rules file: %s<br>' % (rules_url,))
        print('[D] Valid/invalid rules count: %s/%s, definitions count: %s<br>' % (
            len(rules), len(invalid_rules), len(definitions)))
        print('[I] My hostname: %s, IP address: %s, "Class": %s<br></p>' % (
            myhostname, myipaddress, myclass))
        #print_definitions(definitions)
        #pprint.pprint(invalid_rules)
        for rule in rules:
            if rule.is_checkable:
                status, report1 = check_rule(rule, definitions)
                if not status:
                    print('<H3 style="color:red">[FAIL] %s</H3><br>' % rule.raw_rule)
                    print('<pre>%s' % report1)
                    #for k, v in scan_result_by_state.items():
                    #    if len(v['close']) > 0:
                    #        print('<B>HOST</B>: %s, <B>ZART PORTOK</B>: %s' % (k, str(v['close'])))
                    print('</pre>')
                else:
                    print('<H3 style="color:green">[OK] %s</H3><br>' % rule.raw_rule)
            elif args.verbose:
                print('<H3 style="color:grey">[NOT CHECKED] %s</H3><br>' % rule.raw_rule)
        print('</BODY></HTML>')
    elif args.mode_desc == 'raw':
        for rule in rules:
            if rule.is_checkable:
                check_rule(rule, definitions)

        if args.raw_order == 'byport':
            pprint.pprint(scan_result_by_port)
        elif args.raw_order == 'bystate':
            pprint.pprint(scan_result_by_state, width=60)

    if args.diag:
        print('DIAG DATA')
        print('Printing parsed checked rules')
        for rule in rules:
            if rule.is_checkable:
                print_parsed_rule(rule)
        print('Printing parsed unchecked rules')
        #for rule in rules:
        #    if not rule.is_checkable:
        #        print_parsed_rule(rule)

        print('Printing invalid rules')
        pprint.pprint(invalid_rules)

        print('RULES')


if __name__ == '__main__':
    main()