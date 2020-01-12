#!/usr/bin/python3

import base64, json, pprint, docker, logging, socket, time
from flask import Flask, jsonify, request
from concurrent.futures import ThreadPoolExecutor
from eap import *


REAUTH_INTERVAL = 10     # reauthentication intervall in seconds
AS_IP = "2001:db8::1"    # switch address
#AS_IP = "ff02::1%ens10"  # All Routers Adressen, addressed all Router in link-lokal (inside a subnet)
AS_PORT = 50000          # EAPoUDP port
BUFFER_SIZE = 4096       # in bytes


# see: https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.ThreadPoolExecutor
executor = ThreadPoolExecutor()

logging.basicConfig(format='%(asctime)s %(levelname)s@%(funcName)s: %(message)s',
                    filename='authz.log', level=logging.INFO)

app = Flask(__name__)
application = app


@app.route('/')
def index():
    print("/")
    return 'Docker Authz Plugin\n'

@app.route('/Plugin.Activate', methods=['POST'])
def activate():
    logging.info("/Plugin.Activate")
    return jsonify({'Implements': ['authz']})

def decode_request(request):
    req_data = json.loads(request.data.decode('utf-8'))
    if 'RequestBody' in req_data:
        req_data['RequestBody'] = json.loads(base64.b64decode(req_data['RequestBody']).decode('utf-8'))
    if 'ResponseBody' in req_data:
        req_data['ResponseBody'] = json.loads(base64.b64decode(req_data['ResponseBody']).decode('utf-8'))
    return req_data

#This authorize request method is called before the Docker daemon processes the client request.
@app.route('/AuthZPlugin.AuthZReq', methods=['POST'])
def authz_request():
    req_data = decode_request(request)
    print("data dump:\n\t{}\n".format(pprint.pformat(req_data)))

    response = {'Allow': True, 'Msg': "Msg: The request authorization succeeded."}

    ## optional restiction of 'busybox' images
    ##TODO: remove this restiction
    #if ('RequestBody' in req_data and
    #    'Image' in req_data['RequestBody'] and
    #    req_data['RequestBody']['Image'] != 'busybox'):
    #    logging.warning("No 'busybox'-Image ({}), request denied!"
    #                    .format(req_data['RequestBody']['Image']))
    #    response = {'Allow': False,
    #                'Msg': "Msg: The request authorization failed. Only busyboxes allowed (no {})!"
    #                       .format(req_data['RequestBody']['Image']),
    #                'Err': "Err: You must run a 'busybox' image."}

    return jsonify(**response)

#This authorize response method is called before the response is returned from Docker daemon to the client.
@app.route('/AuthZPlugin.AuthZRes', methods=['POST'])
def authz_response():
    req_data = decode_request(request)
    print("data dump:\n\t{}\n".format(pprint.pformat(req_data)))

    response = {'Allow': True}  # always allowed by default

    # check for 'start' event
    uri = req_data['RequestUri'].split('/')
    if uri[1] != '_ping' and uri[2] == 'containers' and uri[-1].startswith('create'):

        cid = str(req_data['ResponseBody']['Id'])
        cli = docker.from_env()
        c = cli.containers.get(cid)

        # get container credentials
        authz_user, authz_pass, data = get_authz_data(c)

        # authenticate container, if user and password are given
        if authz_user != "" and authz_pass != "":
            # start first EAPoUDP authentication
            ok, reply_msg = eap_over_udp(authz_user, authz_pass, data)
            if ok:
                print("[+] Authentication successfully completed.")
                # start reauthentication
                executor.submit(reauthz, c, authz_user, authz_pass, data)
            else:
                response = {'Allow': False, 'Msg': reply_msg}
        else:
            print("no credentials, no authentication! id={}".format(c.id))

    return jsonify(**response)

def get_authz_data(c):
    authz_user = ""
    authz_pass = ""
    data = ""
    for env in c.attrs.get("Config").get("Env"):
        if env.startswith("AUTHZ_USER="): authz_user = env[len("AUTHZ_USER="):]
        if env.startswith("AUTHZ_PASS="): authz_pass = env[len("AUTHZ_PASS="):]
        if env.startswith("ipv6="): ipv6 = env[len("ipv6="):]
    data += "name={}".format(c.attrs.get("Name")[1:])
    data += ",ip={}".format(ipv6)
    data += ",image={}".format(c.attrs.get("Config").get("Image"))
    data += ",image-id={}".format(c.attrs.get("Image"))
    print("dump authz data for container: " +
                 "id={}\n\tauthz_user = {}\n\tauthz_pass = {}\n\tauthz_data = {}"
                 .format(c.id, authz_user, authz_pass, data))
    return authz_user, authz_pass, data

def eap_over_udp(authz_user, authz_pass, data):
    ok = False
    reply_msg = ""
    with get_connection() as s:
        # Send data
        print("0: sending EAPoUDP start packet...")
        s.sendall(bytes())
        while True:
            s, packet = get_gesponse_packet(s)
            if packet is None:
                logging.warning("got None packet! restart EAPoUDP...")
                s.sendall(bytes())
                continue
            logging.info("packet recived: {}".format(packet))
            if packet.code == EAP_CODE.REQUEST:
                if packet.type == EAP_TYPE.IDENTITY:
                    logging.info("1: sending IDENTITY response packet...")
                    s.sendall(bytes(EAP(eap_code=EAP_CODE.RESPONSE, identifier=packet.id,
                                        eap_type=EAP_TYPE.IDENTITY, data=authz_user)))
                elif packet.type == EAP_TYPE.MD5CHALLENGE:
                    #TODO: split data in extra parameter
                    logging.info("2: sending MD5CHALLENGE response packet...")
                    s.sendall(bytes(EAP(eap_code=EAP_CODE.RESPONSE, identifier=packet.id,
                                        eap_type=EAP_TYPE.MD5CHALLENGE, data=data,
                                        challenge=EAP.calc_md5_challenge(
                                            packet.id, authz_pass, packet.challenge))))
                elif packet.type == EAP_TYPE.NOTIFICATION:
                    reply_msg = packet.data.decode("utf-8")
                    logging.info("received NOTIFICATION: {}".format(reply_msg))
                    logging.info("sending NOTIFICATION response packet...")
                    s.sendall(bytes(EAP(eap_code=EAP_CODE.RESPONSE, identifier=packet.id,
                                        eap_type=EAP_TYPE.NOTIFICATION, data="")))
                else:
                    logging.warning("unknown or not implemented request type: {} ! aborting...".format(packet.type))
                    break
            elif packet.code == EAP_CODE.SUCCESS:
                logging.info("Authentification successed! \o/")
                ok = True
                break
            elif packet.code == EAP_CODE.FAILURE:
                logging.info("Authentification failed! :-(")
                break
            else:
                logging.warning("unknown or not implmented EAP code: {}! aborting...".format(packet.code))
                break
    return ok, reply_msg

def get_connection():
    print("function get_connection()")
    print("try to connect to: ip={} port={}".format(AS_IP, AS_PORT))
    # Create a UDP socket
    # from https://docs.python.org/3.6/library/socket.html
    s = None
    for res in socket.getaddrinfo(AS_IP, AS_PORT, socket.AF_INET6, socket.SOCK_DGRAM):
        logging.debug("addrinfo: {}".format(res))
        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
        except OSError as msg:
            s = None
            continue
        try:
            s.connect(sa)
        except OSError as msg:
            s.close()
            s = None
            continue
        break
    if s is None:
        print("could not open socket")
    return s

def get_gesponse_packet(s):
    logging.debug("waiting for response...")
    r = None
    try:
        r = EAP(parse=s.recv(BUFFER_SIZE))
        logging.debug(r)
    except ValueError as err:
        logging.error("can't parse response as EAP packet! ValueError: {}".format(err))
    return (s,r)

def unpause_container(c):
    c.reload()
    if c.status == 'paused':
        c.unpause()
        c.reload()
        logging.info("unpaused container, now: {} id={}".format(c.status, c.id))

def reauthz(c, authz_user, authz_pass, data):
    while True:
        print("start reauthentification in {} seconds for container id={}".format(REAUTH_INTERVAL, c.id))
        time.sleep(REAUTH_INTERVAL)
        # is conainer still running?
        print("try to reload container {}".format(c.id))
        try:
            c.reload()
            print("container: {} id={}".format(c.status, c.id))
        except Exception as err:
            print(err) # 404 Client Error: Not Found ("No such container: 916...")
            print("so, i'm not needed anymore... done \o/")
            break
        # perform reauthentication
        ok, reply_msg = eap_over_udp(authz_user, authz_pass, data)
        if not ok:
            print("Reauthentication faild: {}; killing container id={}; done \o/".format(reply_msg, c.id))
            unpause_container(c)
            c.kill()
            break
   
if __name__ == '__main__':
    print("starting authz plugin")
    logging.info("starting authz plugin")
    app.run()
