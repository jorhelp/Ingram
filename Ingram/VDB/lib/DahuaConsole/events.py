import _thread
from utils import *
from connection import DahuaConnect


class DahuaEvents(DahuaConnect):
    def __init__(self):
        super(DahuaEvents, self).__init__()

    def internal_event_manager(self, dh_data):
        """ JSON fixing part, then feed 'local_event_handler()' """

        try:
            events = fix_json(dh_data)
            for event in events:
                self.local_event_handler(event)
        except Exception as e:
            log.failure('[internal_event_manager] {}'.format(repr(e)))

    def local_event_handler(self, dh_data):
        """ Local event handler """
        try:
            host = dh_data.get('host')
            event_list = dh_data.get('params').get('eventList')

            for events in event_list:
                if events.get('Action') == 'Start':
                    """
                    Reboot event, remote device is already rebooting and we cannot make clean exit,
                    so just close instance and reschedule connection
                    """
                    if events.get('Code') == 'Reboot':
                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), LYELLOW),
                            color(host, GREEN),
                            color('Reboot', RED),
                        ))
                        tmp = False

                        session = None
                        for session in self.dhConsole:
                            if self.dhConsole.get(session).get('host') == host:
                                log.warning(
                                    "{}: {} ({})".format(
                                        session,
                                        self.dhConsole.get(session).get('device'),
                                        self.dhConsole.get(session).get('host')))

                                tmp = self.dhConsole.get(session).get('instance')
                                tmp.terminate = True
                                tmp.logout()
                                break
                        if tmp:
                            if tmp == self.dh:
                                del self.dh
                                self.dhConsole.pop(session)

                                if len(self.dhConsole):
                                    for session in self.dhConsole:
                                        self.dh = self.dhConsole.get(session).get('instance')
                                        break
                            else:
                                del tmp
                                self.dhConsole.pop(session)

                        # _thread.start_new_thread(self.restart_connection, ("restart_connection", host,))
                        _thread.start_new_thread(self.restart_connection, (host,))

                    elif events.get('Code') == 'Exit':

                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('Exit App', RED)
                        ))
                    elif events.get('Code') == 'ShutDown':

                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('ShutDown App', RED)
                        ))
                    # VTO
                    elif events.get('Code') == 'AlarmLocal':

                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('AlarmLocal [Start]', RED)
                        ))
                    # VTO
                    elif events.get('Code') == 'ProfileAlarmTransmit':
                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color(
                                'ProfileAlarmTransmit [Start]\n'
                                'AlarmType: {}, DevSrcType: {}, SenseMethod: {}, UserID: {}'.format(
                                    events.get('Data').get('AlarmType'),
                                    events.get('Data').get('DevSrcType'),
                                    events.get('Data').get('SenseMethod'),
                                    events.get('Data').get('UserID'),
                                ), RED)
                        ))
                    elif events.get('Code') == 'SafetyAbnormal':
                        log.warning('[{} ({}) Start ] {}'.format(
                            color(
                                events.get('Data').get('AbnormalTime')
                                if events.get('Data').get('AbnormalTime') else events.get('Data').get('LocaleTime'),
                                YELLOW
                            ),
                            color(host, GREEN),
                            color('{} {}'.format(
                                events.get('Data').get('ExceptionType'),
                                events.get('Data').get('Address')
                            ), RED),
                        ))

                elif events.get('Action') == 'Stop':

                    # VTO
                    if events.get('Code') == 'AlarmLocal':

                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('AlarmLocal [Stop]', GREEN)
                        ))

                    # VTO
                    elif events.get('Code') == 'ProfileAlarmTransmit':
                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color(
                                'ProfileAlarmTransmit [Stop]\n'
                                'AlarmType: {}, DevSrcType: {}, SenseMethod: {}, UserID: {}'.format(
                                    events.get('Data').get('AlarmType'),
                                    events.get('Data').get('DevSrcType'),
                                    events.get('Data').get('SenseMethod'),
                                    events.get('Data').get('UserID'),
                                ), GREEN)
                        ))

                    elif events.get('Code') == 'SafetyAbnormal':
                        log.warning('[{} ({}) Stop ] {}'.format(
                            color(
                                events.get('Data').get('AbnormalTime')
                                if events.get('Data').get('AbnormalTime') else events.get('Data').get('LocaleTime'),
                                YELLOW
                            ),
                            color(host, GREEN),
                            color('{} {}'.format(
                                events.get('Data').get('ExceptionType'),
                                events.get('Data').get('Address')
                            ), RED),
                        ))

                elif events.get('Action') == 'Pulse':

                    if events.get('Code') == 'SafetyAbnormal':
                        log.warning('[{} ({}) ] {}'.format(
                            color(
                                events.get('Data').get('AbnormalTime')
                                if events.get('Data').get('AbnormalTime') else events.get('Data').get('LocaleTime'),
                                YELLOW
                            ),
                            color(host, GREEN),
                            color('{} {}'.format(
                                events.get('Data').get('ExceptionType'),
                                events.get('Data').get('Address')
                            ), RED),
                        ))

                    elif events.get('Code') == 'LoginFailure':
                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('Login Failure: {} {} ({})'.format(
                                events.get('Data').get('Name'),
                                events.get('Data').get('Address'),
                                events.get('Data').get('Type')
                            ), RED),
                        ))

                    elif events.get('Code') == 'RemoteIPModified':
                        log.warning('[{} ({}) ] {}\n{}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('DHDiscover.setConfig', YELLOW),
                            events.get('Data'),
                        ))

                    elif events.get('Code') == 'Reset':
                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('Factory default reset', RED),
                        ))

                    # VTH
                    elif events.get('Code') == 'InfoTip':
                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('InfoTip', YELLOW),
                        ))
                    # VTH
                    elif events.get('Code') == 'KeepLightOn':
                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('KeepLightOn: {}'.format(events.get('Data').get('Status')), YELLOW),
                        ))
                    # VTH
                    elif events.get('Code') == 'ScreenOff':
                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('ScreenOff', YELLOW),
                        ))
                    # VTH
                    elif events.get('Code') == 'VthAlarm':
                        log.warning('[{} ({}) ] {}'.format(
                            color(events.get('Data').get('LocaleTime'), YELLOW),
                            color(host, GREEN),
                            color('VTH Alarm', RED),
                        ))

        except Exception as e:
            log.failure('[local_event_handler] {}'.format(repr(e)))
            pass
