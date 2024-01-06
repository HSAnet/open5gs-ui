Retrieving and processing systemd-logs
**************************************


Open5Gs Network function logs
=============================

.. role:: raw-html(raw)
   :format: html


.. figure:: /media/5g-network-functions.png
   :alt: Image of 5G Network Functions.

   The 5G-Core-Unit consists of several Network-function as shown in this image, e.g. UPF, AMF…
   :raw-html:`<br />`
   The gNB (or GNodeB) and the UE (User Equipment) are however not part of the core. [1]_

Each network function and its corresponding Linux service writes log data to the ``/var/log/open5gs/`` directory.
These log files can be accessed either by directly reading the files (which requires root access) or by using the
``journalctl`` command. The ``journalctl`` command takes approximately 300 times longer than simply reading the log files
directly. Due to the possibility of changing settings and therefore variable log destinations, the tool first attempts
to locate the log files in the provided directory. If no log files are found, the tool then executes the ``journalctl``
command.

|

open5g_rake
===========

.. figure:: /media/open5gslog_arch.svg
   :alt: Architecture Observer and rake of systemd-logs
   :class: with-border

   The diagram illustrates the fundamental principle of the open5g_rake module. The user creates an Open5GRake
   instance, which enables the caller to directly access the log data via the ``rake_raw()`` function or parse it
   into a validated RFC 8259 JSON string using the ``rake_json()`` function. Upon initialization, Open5GRake
   creates a list of Service objects based on systemd's output. Each service instance can retrieve its log
   data and pass it back when necessary.

Service-Object
--------------

The ``Service-Object`` is utilized to streamline access to systemd-service data (status/logs). The function
``__get_status()`` is invoked to update its private attribute ``__status``, which retains information pertaining to
the service.

Status
++++++

- status - The service is either active or inactive
- since - When the service starts or ends a date is stored
- memory - The memory used by the service
- cpu - Amount in milliseconds the service used on the CPU

.. code-block:: python
   :caption: __get_status()

   result = Bash().run(BashCommands.CTL_STATUS.value.format(service_name=self.service_name))

The ``Bash().run()`` executes the bash command ``systemctl status open5gs-upfd.service`` which has different
output strings for active and inactive services.

.. code-block:: Bash
   :caption: ``systemctl status open5gs-upfd.service`` output (when active)
   :emphasize-lines: 3, 6, 7

   ● open5gs-upfd.service - Open5GS UPF Daemon
     Loaded: loaded (/lib/systemd/system/open5gs-upfd.service; enabled; vendor preset: enabled)
     Active: active (running) since Sat 2024-01-06 03:20:23 CET; 58min ago
   Main PID: 2948 (open5gs-upfd)
      Tasks: 2 (limit: 2200)
     Memory: 2.0M
        CPU: 189ms
     CGroup: /system.slice/open5gs-upfd.service
             └─2948 /usr/bin/open5gs-upfd -c /etc/open5gs/upf.yaml

.. code-block:: Bash
   :caption: ``systemctl status open5gs-upfd.service`` output (when inactive)
   :emphasize-lines: 3, 6

   ○ open5gs-upfd.service - Open5GS UPF Daemon
     Loaded: loaded (/lib/systemd/system/open5gs-upfd.service; enabled; vendor preset: enabled)
     Active: inactive (dead) since Sat 2024-01-06 04:46:29 CET; 5s ago
    Process: 2948 ExecStart=/usr/bin/open5gs-upfd -c /etc/open5gs/upf.yaml (code=exited, status=0/SUCCESS)
   Main PID: 2948 (code=exited, status=0/SUCCESS)
        CPU: 261ms

As demonstrated above, the most significant element missing for an inactive service is the memory portion,
which necessitates consideration in the regular expression pattern.

.. code-block:: python
   :caption: status regex pattern

   status_pattern = re.compile(r'Active:\s'                            # Looking for Active: with a trailing whitespace
                               r'(?P<status>\w+)'                      # Followed by (active/inactive) and grouped
                               r'.*?'                                  # Followed by a random amount of character
                               r'(?<=since)[\D\s]*'                    # The date is prefixed by since and an abbreviation of the day
                               r'(?P<date>[\d\s\-:]+)'                 # The date consists of digits, whitespaces and the
                                                                       # character [-:]. Includes trailing whitespace.
                               r'(.*?Memory:\s(?P<memory>[\d.]+))?'    # The Memory info only exists if the service is active -> ()?
                               r'.*?'                                  # Randon number of characters
                               r'CPU:\s'                               # Followed by CPU with a trailing whitespace
                               r'(?P<cpu>\d+)'                         # Only grab the digits and group it.
                               ,re.DOTALL | re.VERBOSE)

The ``VERBOSE``-Flag enables documentation of the regular expression line by line. The ``DOTALL``-Flag is employed
because the bash-commands return value includes line separators, but the pattern is simple enough to be parsed in
a single iteration.

Logs
++++

Log data exhibits subtle variations depending on the method of access. ``journalctl`` displays the log date at the
beginning of the string. The .log file also starts with a date, but the format differs. To match log entries with
the same date, the regular expression does not assume the date to be at the beginning of the string.

.. code-block:: sh
   :caption: log string from journalctl and .log file

   # journalctl log
   01/05 19:46:53.583: [app] INFO: Configuration: '/etc/open5gs/amf.yaml' (../lib/app/ogs-init.c:130)
   # file log
   Jan 05 19:46:53 Open5Gs open5gs-amfd[3266]: 01/05 19:46:53.687: [app] INFO: Configuration: '/etc/open5gs/amf.yaml' (../lib/app/ogs-init.c:130)

.. code-block:: python
   :caption: regex log_pattern to parse log string

   log_pattern = re.compile(r'(?P<date>\d{2}/\d{2})'                    # The log date consists of day and mont like 30/02
                            r'\s'                                       # Followed by a whitespace char
                            r'(?P<time>[\d:]+)'                         # The time consists of digits and ':'
                            r'.*?'                                      # Random info between time and log-level
                            r'(?P<level>DEBUG|INFO|WARNING|CRITICAL)'   # The log-level is one of the listed words
                            r':\s'                                      # Followed by a whitespace char
                            r'(?P<msg>.*)',                             # The rest of the line is the log message
                            re.MULTILINE | re.VERBOSE)

The ``__parse_log_data()`` function enables parsing either all available logs or filtering out logs older than
the specified time_delta (an integer value in seconds). The lambda expression in lines 2 and 3 implements
this filtering mechanism. To compare and subtract from the log date, a conversion to a datetime object is
necessary. However, the dictionary containing the log information is more versatile when it does not use a
datetime object, which is why it is converted back into a string format.

.. code-block:: python
   :linenos:
   :emphasize-lines: 2, 3
   :caption: private ``__parse_log_data()`` function

   def __parse_log_data(self, log_data: str, time_delta: Union[int, None])
      is_new_log: Callable[[datetime], bool] = lambda lg_ts: True if not time_delta else (
                lg_ts > (datetime.now() - timedelta(seconds=time_delta)))
        return [{'date': log_date.strftime('%d.%m.%Y %H:%M:%S'),
                 'level': match.group('level'),
                 'msg': match.group('msg')
                 } for line in log_data.splitlines() if (match := log_pattern.search(line)) and
                is_new_log((log_date := datetime.fromisoformat(f'{datetime.now().year}'
                                                               f'{match.group('date').replace('/', '')} '
                                                               f'{match.group('time')}')))]

JSON
++++

Python offers multiple approaches to parse data into JSON format. Typically, the ``json.dumps()`` function from the
json package utilizes the ``Object.__dict__()`` method to determine how to serialize the object. However, this method
fails to handle complex objects. Alternatively, an encoder object can be implemented, but for this project, a
hybrid approach involving self-creation and json.dumps() is employed. Complex attributes are extracted individually,
and the logs, which are already structured as a list of dictionaries, are converted using the ``json.dumps()`` function.


.. code-block:: python
   :caption: to_json() function for parsing Service-Object (status and logs) into json string

   def to_json(self, time_delta: Union[int, None]) -> str:
      return (f"{{\"Name\": \"{self.service_name}\",\"Status\": \"{self.__status['status']}\",\""
              f"{'Up' if self.status['status'] else 'Down'} "
              f"since\": \"{self.__status['since']}\","
              f"\"CPU usage\": \"{self.__status['cpu']}\","
              f"\"Mem usage\": \"{'0' if not self.__status['memory'] else self.__status['memory']}\","
              f"\"logs\": {json.dumps([log for log in self.get_logs(time_delta)])}"
              f"}}")

In order to use the python f-string, it is necessary to escape curly-brackets with another curly-bracket, which
is why the beginning and the end of the string contain {{ and }}.

Rake-Object
-----------

init
++++

On initialization, the rake looks up all open5Gs services by executing the bash command
``systemctl list-units open5gs-* --all``. The output looks as follows.


.. code-block:: sh
   :caption: ``systemctl list-units open5gs-* --all`` output, with upf-service stopped

   UNIT                  LOAD   ACTIVE   SUB     DESCRIPTION
   open5gs-amfd.service  loaded active   running Open5GS AMF Daemon
   open5gs-ausfd.service loaded active   running Open5GS AUSF Daemon
   open5gs-bsfd.service  loaded active   running Open5GS BSF Daemon
   open5gs-hssd.service  loaded active   running Open5GS HSS Daemon
   open5gs-mmed.service  loaded active   running Open5GS MME Daemon
   open5gs-nrfd.service  loaded active   running Open5GS NRF Daemon
   open5gs-nssfd.service loaded active   running Open5GS NSSF Daemon
   open5gs-pcfd.service  loaded active   running Open5GS PCF Daemon
   open5gs-pcrfd.service loaded active   running Open5GS PCRF Daemon
   open5gs-scpd.service  loaded active   running Open5GS SCP Daemon
   open5gs-sgwcd.service loaded active   running Open5GS SGW-C Daemon
   open5gs-sgwud.service loaded active   running Open5GS SGW-U Daemon
   open5gs-smfd.service  loaded active   running Open5GS SMF Daemon
   open5gs-udmd.service  loaded active   running Open5GS UDM Daemon
   open5gs-udrd.service  loaded active   running Open5GS UDR Daemon
   open5gs-upfd.service  loaded inactive dead    Open5GS UPF Daemon
   open5gs-webui.service loaded active   running Open5GS WebUI


.. code-block:: python
   :linenos:
   :caption: private function ``__get_service_list()``

   def __get_service_list(self) -> None:
      result = Bash().run(BashCommands.OPENFIVEGSERVICES.value)
      for line in result.splitlines()[1:17]:
          tmp = self.__split_pattern.split(line.strip())
          self.__service_list.append(Service(service_name=tmp[0], log_file=None if not self.__path else self.__path / tmp[5].lower()))

By using a simple regular expression ``self.__split_pattern = re.compile(r'\s+')``, the individual lines are split
regardless of the number of whitespace characters encountered. Subsequently, `Service-Object`_\s are instantiated and
stored in a list.

Usage
+++++

.. code-block:: python
   :caption: Example on how to retrieve log files form open5gs-services

   import open5g_rake as rake
   from pathlib import Path

    o_rake = rake.Open5GRake()
    # o_rake = rake.Open5GRake(log_files_dir=Path('/var/log/open5gs/))
    while True:
        time.sleep(5)
        try:
            print(o_rake.rake_json(time_delta=100))
            # for log in o_rake.rake_raw(time_delta=100):
            #     print(log)
        except rake.Open5gsException as e:
            print(e.msg)

The Open5GRake object can be initialized either with or without a specific log file path. Once initialized,
the log data can be retrieved at any time using the ``rake_json()`` or ``rake_raw()`` methods.

rake_raw() output
_________________

.. code-block:: python
   :caption: ``rake_raw()`` output. Dictionaries containing the date, log-level and the message of the logs

   {'date': '2024-01-06 08:26:34', 'level': 'WARNING', 'msg': 'Retry association with peer [127.0.0.7]:8805 failed (../src/smf/pfcp-sm.c:110)'}
   {'date': '2024-01-06 08:26:42', 'level': 'WARNING', 'msg': '[229] LOCAL  No Reponse. Give up! for step 1 type 5 peer [127.0.0.7]:8805 (../lib/pfcp/xact.c:606)'}
   {'date': '2024-01-06 08:26:45', 'level': 'WARNING', 'msg': 'Retry association with peer [127.0.0.7]:8805 failed (../src/smf/pfcp-sm.c:110)'}
   {'date': '2024-01-06 08:26:53', 'level': 'WARNING', 'msg': '[230] LOCAL  No Reponse. Give up! for step 1 type 5 peer [127.0.0.7]:8805 (../lib/pfcp/xact.c:606)'}

rake_json() output
__________________

.. code-block:: json
   :caption: ``rake_json()`` output (Not the full output, typically there are 17 open5gs-services. The output also does not contain indentation)
   :linenos:

   {
     "services": {
       "service": [
         {
           "Name": "open5gs-amfd.service",
           "Status": "True",
           "Up since": "2024-01-06 07:44:57",
           "CPU usage": "148",
           "Mem usage": "1.5",
           "logs": []
         },
         {
           "Name": "open5gs-smfd.service",
           "Status": "True",
           "Up since": "2024-01-06 07:44:57",
           "CPU usage": "1",
           "Mem usage": "3.9",
           "logs": [
             {
               "date": "2024-01-06 08:19:14",
               "level": "WARNING",
               "msg": "Retry association with peer [127.0.0.7]:8805 failed (../src/smf/pfcp-sm.c:110)"
             },
             {
               "date": "2024-01-06 08:20:50",
               "level": "WARNING",
               "msg": "[197] LOCAL  No Reponse. Give up! for step 1 type 5 peer [127.0.0.7]:8805 (../lib/pfcp/xact.c:606)"
             }
           ]
         },
         {
           "Name": "open5gs-upfd.service",
           "Status": "False",
           "Down since": "2024-01-06 08:07:27",
           "CPU usage": "139",
           "Mem usage": "0",
           "logs": []
         }
       ]
     }
   }



.. [1] „5G Network Architecture. Core, RAN & Security Architecture for 5G“, VIAVI Solutions Inc., 5. Dezember 2023. https://www.viavisolutions.com/en-us/what-5g-architecture