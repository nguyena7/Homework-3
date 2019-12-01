from rawsocket import RawSocket
import time

def main():
    remotehost = "www.google.com"
    raw = RawSocket(remotehost)
    raw.trace()
    print("Trace Complete")

if __name__ == "__main__":
    main()
