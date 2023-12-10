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

Each network-function and their associated linux service writes log data to **/var/log/open5gs/**.
These log files can be accessed either by reading the files directly (requires root access) or by
**journalctl**. The journalctl command compared to simply reading the log-files takes around 300 times
longer. Due to changing setting and therefore variable log-destinations the tool tries to find the
log files in the provided directory, and if nothing was found it executes the journalctl command.

|

.. figure:: /media/arch_sys_log.svg
   :alt: Architecture Observer and rake of systemd-logs
   :class: with-border

   The diagram displays the architecture of the systemd-log-rake. The Observer requests new log data,
   the rake first asks the FileReader if there are any new logs, however if for some reason the FileReader
   fails or does not find any files, journalctl is executed to find log data.


Implementation
==============

The rake function at first tries to read the log files. If the user doesn't have permission or the files do not exist
**journalctl -u open5gs-service_name.service -b** instead is executed. **(Files in /var/log/open5gs typically need root privileges)**.
The reason for two different/similar function parameters is that, some of Open5Gs-systemd-services are
named like *open5gs-upfd.service or open5gs-smfd-service ...*. However, the log-files are named *upf.log or amf.log ...*,

.. code-block:: python
   :linenos:

   def rake(self, service_name: str, net_fun_name: str) -> str:
      logs, log_error = self.__file_reader(net_fun_name=net_fun_name)
      return logs if not log_error else Bash().run(
          BashCommands.CTLSERVICELOG.value.format(service_name=service_name))

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




.. [1] „5G Network Architecture. Core, RAN & Security Architecture for 5G“, VIAVI Solutions Inc., 5. Dezember 2023. https://www.viavisolutions.com/en-us/what-5g-architecture