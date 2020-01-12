import sys
from ryu.cmd import manager


def main():
    #sys.argv.append("simple_switch_13.py")
    #sys.argv.append("test.py")
    sys.argv.append("EAPoUDP.py")
    sys.argv.append("--verbose")
    sys.argv.append("--enable-debugger")
    sys.argv.append("--ofp-tcp-listen-port")  # openflow tcp listen port
    sys.argv.append("6653")  # default: 6653
    manager.main()


if __name__ == "__main__":
    main()
