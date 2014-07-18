#!/usr/bin/env python

import dbus
import sys
import argparse

def notify(summary, body='', app_name='', app_icon='',
           timeout=500, actions=[], hints={}, replaces_id=0):
    _bus_name = 'org.freedesktop.Notifications'
    _object_path = '/org/freedesktop/Notifications'
    _interface_name = _bus_name

    session_bus = dbus.SessionBus()
    obj = session_bus.get_object(_bus_name, _object_path)
    interface = dbus.Interface(obj, _interface_name)
    interface.Notify(app_name, replaces_id, app_icon,
                     summary, body, actions, hints, timeout)



def parse_args():
    description = "Simple dbus notification client"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-p', '--priority',
                        dest='priority',
                        const='1',
                        choices=['0', '1', '2'],
                        nargs='?',
                        default='1',
                        metavar='priority',
                        help='Set message priority')
    parser.add_argument('-i', '--icon',
                        dest='icon',
                        metavar='icon',
                        default='/usr/share/icons/oxygen/64x64/actions/chronometer.png',
                        nargs='?',
                        help='A preferably 32x32 icon to display')
    parser.add_argument('-s', '--summary',
                        dest='summary',
                        metavar='summary',
                        default='',
                        help='Message summary')
    parser.add_argument('message',
                        nargs='*',
                        help='Notification message')
    return parser, parser.parse_args()


# If run as a script, just display the argv as summary
if __name__ == '__main__':
    parser, args = parse_args()

    summary = args.summary
    body = ' '.join(args.message).strip().decode('utf-8')
    app_icon = args.icon
    priority = dbus.Byte(args.priority)
    hints = {
        'urgency': priority,
        'transient': dbus.Boolean(1)
    }

    notify(summary=summary, body=body, hints=hints, app_icon=app_icon)
