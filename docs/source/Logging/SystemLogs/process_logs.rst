Retrieving and processing systemd-logs
######################################


Open5Gs Network function logs
*****************************

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

.. figure:: /media/open5gslog_arch.svg
   :alt: Architecture Observer and rake of systemd-logs
   :class: with-border

   The diagram illustrates the fundamental principle of the open5g_rake module. The user creates an Open5GRake
   instance, which enables the caller to directly access the log data via the ``rake_raw()`` function or parse it
   into a validated RFC 8259 JSON string using the ``rake_json()`` function. Upon initialization, Open5GRake
   creates a list of Service objects based on systemd's output. Each service instance can retrieve its log
   data and pass it back when necessary.

Implementation
==============

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

.. code-block:: sh

   # journalctl log
   01/05 19:46:53.583: [app] INFO: Configuration: '/etc/open5gs/amf.yaml' (../lib/app/ogs-init.c:130)
   # file log
   Jan 05 19:46:53 Open5Gs open5gs-amfd[3266]: 01/05 19:46:53.687: [app] INFO: Configuration: '/etc/open5gs/amf.yaml' (../lib/app/ogs-init.c:130)


Json
++++






.. code-block:: python
   :linenos:

   def rake(self, service_name: str, net_fun_name: str) -> str:
      logs, log_error = self.__file_reader(net_fun_name=net_fun_name)
      return logs if not log_error else Bash().run(
          BashCommands.CTLSERVICELOG.value.format(service_name=service_name))

The rake function initially attempts to read the log files. If the user lacks the necessary permissions or the files
do not exist, ``journalctl -u open5gs-service_name.service -b`` is executed instead. (Files in the ``/var/log/open5gs``
directory typically require root privileges.) The reason for using two different yet similar function parameters
is that some Open5G systemd services, such as open5gs-upfd.service or open5gs-smfd.service, have different names
than the corresponding log files, such as upf.log or amf.log.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4, 5, 6, 7

   def get_logs(self, service_name: str) -> Tuple[str, bool]:
      ret_value: str = ''
      log_error: bool = True
      zipped: Callable[[Path], bool] = lambda file_name: '.gz' == file_name.suffix
      for path in [log_file for log_file in self.__log_dir.glob('*')
                  if not zipped(log_file)
                  and net_fun_name.lower() in str(log_file)][1::-1]:
         log_error = False
         try:
             with path.open() as f:
                 ret_value += f.read()
         except PermissionError:
             self.__rake_logger.warning('Permission denied, cannot access log files!\n'
                                        'Journalctl will be used to retrieve log-data.\n')
             log_error = True
             break
      return ret_value, log_error

The following code example shows the log-file-reader function. The **self.__log_dir** is accessed from
its surrounding class (contains the path of the log files. **default: /var/log/open5gs**.
In line 5 every file in the directory is gathered. Line 6 calls line 4 and makes sure that the file is
not zipped. The system zips old log files, however we are not interested in those. Line 7 then selects
all the gathered files that contain the *word/service_name* provided as argument. Since we are only interested
in the last two log-files, **[1::-1]** selects those and reverses the order. Systemd pushes log-files
downwards regarding their filenames, like [service.log, service.log.1, ... , service.log.n].
If there wasn't any log file found at all, which should not happen, however the user might have changed
the system-log-directory without changing it for this tool, the function returns a True boolean as
second return-value to indicate an error.






.. [1] „5G Network Architecture. Core, RAN & Security Architecture for 5G“, VIAVI Solutions Inc., 5. Dezember 2023. https://www.viavisolutions.com/en-us/what-5g-architecture