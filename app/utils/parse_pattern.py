from enum import Enum
import regex as re


class ParsePattern(Enum):
    SERVICEPATTERN = re.compile("""
                                        (?P<service>                    # Group service
                                            open5gs[-\\w.]+service      # containing open5gs, a random word with separators like '.' or '-' and ends with service
                                        )
                                        \\s+\\w+\\s                     # status is separated by a word and two whitespace chars
                                        (?P<status>                     # Group status
                                            \\w+                        # Consisting of at least 1 char
                                        )
                                        .*?                             # Service name is found somewhere at the end (none greedy)
                                        (?<=5GS\\s)                     # Name of service stands behind 5Gs + whitespace
                                        (?P<s_name>                     # Group s_name
                                            [\\w-]+                     # Service name consists of multiple chars and possible dashes
                                        )
                                        """, re.M | re.VERBOSE)

    TIMESTAMP = re.compile("""
                                    (?P<month>                  # Group month
                                        ^\\w+                   # located at beginning of string consisting of multiple chars
                                    )
                                    \\s                          
                                    (?P<day>                    # Group day 
                                        \\d{2}                  # Consists of 2 digits
                                    )
                                    \\s
                                    (?P<time>                   # Group time
                                        [\\d:]+                 # Consists of multiple digits and ':' etc. (HH:MM:SS)
                                    )
                                    """, re.M | re.VERBOSE)