Config
======

Due to the extensive number of settings required for this project, such as server addresses and ports, network
device names, and other parameters, a purely argument-driven approach is not feasible. Therefore, a configuration
system was implemented to manage these settings in a structured and organized manner.

The configuration file ``settings.conf`` adheres to the `MS-DOS`_ style, supports comments, and is structured as follows:

.. _MS-DOS: https://en.wikipedia.org/wiki/Configuration_file#:~:text=its%20system%20settings.-,MS%2DDOS,-%5Bedit%5D

.. literalinclude:: ../_static/settings.conf
   :language: python
   :caption: setting.conf / configuration file
   :linenos:
   :emphasize-lines: 11, 12

On initialization the ``Config-Object`` parses the ``settings.conf`` using the following pattern.

.. code-block:: python

   _line_pattern = re.compile(r'^(?P<key>\w+)'     # The line starts with a word (cannot be empty)
                                r'\s=\s'           # Followed by an equal sign surrounded by two whitespace chars
                                r'(?P<value>\S*)', # Followed by anything except whitespace (group could be empty)
                                re.M | re.VERBOSE)

The configuration example in line 12 deviates from the expected pattern due to the missing whitespace after the
equal sign. This error will be logged. However, the absence of the BPF_Filter in line 11 is interpreted as an
empty string, effectively disabling filtering.

Each setting will be attached to the Config-Instance and can be access like an attribute. However if a config-key
like in line 12 in the example above does not match the pattern it will raise an AttributeError.

Each configuration setting will be associated with the Config instance and can be accessed directly as an attribute.
However, if a configuration key, such as the one in line 12 of the example provided, does not conform to the expected
pattern, an AttributeError will be raised.



.. code-block:: python
   :caption: Accessing configuration attributes

   conf: Config = Config(Path('./settings.conf'))
   print(dir(conf))
   # Either access values like this
   print('BPF_Filter not found!' if not conf.has('bpf_filter') else conf.bpf_filter)
   # - or - like this
   try:
      print(conf.bpf_filter)
   except AttributeError:
      print('BPF_Filter not found!')
