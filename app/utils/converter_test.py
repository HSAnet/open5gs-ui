
from data_convert import DataConverterInterface, DataConvertWeb, DataConverterLocal


service_example_output = """{
   "services":{
      "service":[
         {
            "Name":"open5gs-amfd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:51",
            "CPU usage":"42",
            "Mem usage":"9.0",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-ausfd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:51",
            "CPU usage":"18",
            "Mem usage":"4.7",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-bsfd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:01:49",
            "CPU usage":"33",
            "Mem usage":"5.9",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-hssd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:54",
            "CPU usage":"111",
            "Mem usage":"8.5",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-mmed.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:51",
            "CPU usage":"109",
            "Mem usage":"12.8",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-nrfd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:01:49",
            "CPU usage":"49",
            "Mem usage":"6.6",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-nssfd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:51",
            "CPU usage":"17",
            "Mem usage":"4.5",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-pcfd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:54",
            "CPU usage":"30",
            "Mem usage":"6.0",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-pcrfd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:54",
            "CPU usage":"138",
            "Mem usage":"8.4",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-scpd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:01:49",
            "CPU usage":"70",
            "Mem usage":"7.8",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-sgwcd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:51",
            "CPU usage":"111",
            "Mem usage":"18.2",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-sgwud.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:51",
            "CPU usage":"104",
            "Mem usage":"16.3",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-smfd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:51",
            "CPU usage":"208",
            "Mem usage":"32.2",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-udmd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:51",
            "CPU usage":"21",
            "Mem usage":"4.8",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-udrd.service",
            "Status":"True",
            "Up since":"2024-01-14 09:03:54",
            "CPU usage":"27",
            "Mem usage":"5.7",
            "logs":[
               
            ]
         },
         {
            "Name":"open5gs-upfd.service",
            "Status":"False",
            "Up since":"2024-01-14 09:03:51",
            "CPU usage":"123",
            "Mem usage":"18.5",
            "logs":[
               
            ]
         }
      ]
   }
}"""



if __name__ == '__main__':
    data_converter: DataConverterInterface = DataConverterLocal()
    print(data_converter.convert_service_data(service_example_output))
