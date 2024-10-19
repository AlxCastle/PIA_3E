import argparse

parser = argparse.ArgumentParser(description="Search IP", \
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-API_KEY", dest="API_KEY", \
                    help="API KEY required to use the Shodan API", required=True)
parser.add_argument("-ports", dest="ports", \
                    help="El puerto que quieres buscar que este abierto", default="80")
params=parser.parse_args()

ports_shodan="port: "+params.ports
APIKEY=params.API_KEY
