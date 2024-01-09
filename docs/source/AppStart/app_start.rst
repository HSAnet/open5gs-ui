Starting / Executing the application
####################################

The log gathering part of the app does not require root privileges, it is however drastically faster
with elevated access rights. The network-sniffer does require root privileges in order to access the
network-adapter. It is recommended to either start the application like **sudo python main.py** or
as the root user.

App help-text
*************

.. code-block:: console

   python main.py --help
   usage: Open5Gs-Log-Observer [-h] [-v] [-q] [-d [DELAY]] [-p] [-V] dest

   positional arguments:
        dest                  server IP or name

   options:
        -h, --help            show this help message and exit
        -v, --verbose         increase verbosity
        -q, --quite           suppress non-critical messages
        -d [DELAY], --delay [DELAY]
                              use delay to reduce load on system
        -p, --port            port of REST-Service
        -V, --version         print version and other info and exit


The application supports numerous options. The **verbose** option will log anything to stdout, however important
(Warning and above) can still be captured in stderr. The **quite** option suppresses any log message, except for
Critical errors which terminate the app. The **delay** is a value in seconds postponing each iteration
of data capturing. The **port** and **dest** are needed to connect to the web-application and its REST interface.