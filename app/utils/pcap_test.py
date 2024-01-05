import py_pcap as pcap
import pandas as pd
import time

if __name__ == '__main__':
    # Example
    pd.set_option('display.max_columns', 500)
    pd.set_option('display.width', 2000)
    try:
        a_obj: pcap.Capture = pcap.capture('enp0s3', [])
        while True:
            time.sleep(5)
            if a_obj.error():
                print(a_obj.get())
            else:
                print(a_obj.get())
    except pcap._utils.NetworkError as ne:
        print(ne)