Starting / Executing the application




.. code-block:: console

   python main.py --help
   usage: Open5Gs-Log-Observer [-h] [-v] [-q] [-d [DELAY]] [-p] [-V] dest

   Open5Gs-Log-Observer version 0.1.0
   Copyright (C) 2023 by TH-Augsburg
   Developer: Jonas Winkler
   Documentation: https://
   GitHub: https://github.com/HSAnet/open5gs-ui

   Supported OS:
            Linux

   This is an open-source tool to read all log-files created by Open5Gs.
   Open5Gs uses systemd services and mongoDB to log information. Both are covered and conveyed

   This tool comes with ABSOLUTELY NO WARRANTY. This is free software, and you
   are welcome to redistribute it under certain conditions. See the
   GNU General Public Licence for details.

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
