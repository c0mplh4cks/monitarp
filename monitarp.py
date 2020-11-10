"""

 MONITARP  -  c0mplh4cks

 a Network Device Detection Tool using ARP

"""





# === Importing Dependencies === #
from sys import path
from socket import socket, AF_PACKET, SOCK_RAW, htons
from time import time, sleep, strftime, gmtime
from threading import Thread
from ipaddress import IPv4Network as ip_range
import argparse

from packet import ARP, ETHERNET, maclookup
from screem import Screen, cursor, text







# === Analyse === #
class Analyse(Thread):
    def __init__(self):
        super().__init__()

        self.data = {}

        self.running = True
        self.error = ""


    def terminate(self):
        self.running = False


    def run(self):
        try:
            while self.running:
                data = monitor.data.copy()
                data_new = data.copy()

                if args.timeout:
                    for ip in data:
                        last = time() - data[ip]["last"]
                        if last >= args.timeout:
                            data_new.pop(ip)

                self.data = data_new.copy()
                sleep(0.2)


        except Exception as err:
            self.error = err







# === Log === #
class Log(Thread):
    def __init__(self):
        super().__init__()

        self.data = {}

        self.running = True
        self.error = ""


    def terminate(self):
        self.running = False


    def read(self, filename, timestamp):
        macs = []

        for i, line in enumerate( open(filename, "r") ):
            if i < 4: continue
            timer, mac, status, times = line.split("\t")[2:]

            if int(times) > timestamp: break
            if status == "ONLINE" and mac not in macs:
                macs.append(mac)
            if status == "OFFLINE" and mac in macs:
                macs.remove(mac)

        return macs


    def run(self):
        try:
            with open(args.log, "w") as f:
                f.write("#\tMONITARP  -  c0mplh4cks\n")
                f.write(f"#\t{ strftime('%d-%m-%y') }\n")
                f.write("\n")
                f.write("\n")


            data_prev = { analyse.data[ip]["mac"] : analyse.data[ip]["last"] for ip in analyse.data }

            while self.running:
                data = { analyse.data[ip]["mac"] : analyse.data[ip]["last"] for ip in analyse.data }

                appeared = data.keys() - data_prev.keys()
                disappeared = data_prev.keys() - data.keys()

                with open(args.log, "a") as f:
                    for mac in appeared:
                        f.write(f"{ strftime('%H:%M:%S') }\t{ mac }\tONLINE\t{ int(time()) }\n")

                    for mac in disappeared:
                        f.write(f"{ strftime('%H:%M:%S') }\t{ mac }\tOFFLINE\t{ int(time()) }\n")


                data_prev = data.copy()

                sleep(1)


        except Exception as err:
            self.error = err







# === Output to File === #
class Output(Thread):
    def __init__(self):
        super().__init__()

        self.running = True
        self.error =""


    def terminate(self):
        self.running = False


    def outputfile(self):
        with open(args.output, "w") as f:
            f.write("#\tMONITARP  -  c0mplh4cks\n")
            f.write(f"#\t{strftime('%d-%m-%y')}\n")
            f.write("#\t\n")
            f.write(f"#\tstealth_mode  :  { args.stealth }\n")
            f.write(f"#\toutput_file   :  { args.output }\n")
            f.write(f"#\tip_range      :  { args.range }\n")
            f.write(f"#\tinterface     :  { args.interface }\n")
            f.write(f"#\tdelay         :  { args.delay }\n")
            f.write(f"#\tmac           :  { args.mac }\n")
            f.write(f"#\tlimit         :  { args.limit }\n")
            f.write(f"#\trepeat        :  { args.repeat }\n")
            f.write("\n")
            f.write("\n")

            for ip in monitor.data:
                mac = monitor.data[ip]["mac"]
                dynamic = monitor.data[ip]["dynamic"]
                first = strftime("%H:%M:%S", gmtime(monitor.data[ip]["first"]))
                last = strftime("%H:%M:%S", gmtime(monitor.data[ip]["last"]))
                vendor = monitor.data[ip]["vendor"]
                f.write(f"{ ip }\t{ mac }\t{ dynamic }\t{ first }\t{ last }\t{ vendor }\n")


    def run(self):
        try:
            while self.running:
                self.outputfile()

                sleep(5)


        except Exception as err:
            self.error = err







# === Monitor === #
class Monitor(Thread):
    def __init__(self):
        super().__init__()

        self.data = {}
        self.s = socket(AF_PACKET, SOCK_RAW, htons(0x0003))

        self.running = True
        self.error = ""


    def terminate(self):
        self.running = False


    def read(self, packet):
        eth = ETHERNET(packet)
        if eth.protocol != 0x0806: return

        arp = ARP(eth.data)
        if args.limit and arp.op != 2: return

        ip, port, mac = arp.src
        if mac == args.mac: return

        info = {
            "mac"       : mac,
            "vendor"    : maclookup(mac),
        }


        return (ip, info)


    def run(self):
        try:
            while self.running:
                packet = self.s.recvfrom(2048)[0]
                result = self.read(packet)

                if result:
                    ip, info = result

                    if not self.data.get(ip):
                        info["dynamic"] = False
                        info["first"] = time()
                        self.data[ip] = info

                    else:
                        if self.data[ip]["mac"] != info["mac"]: self.data[ip]["dynamic"] = True

                    self.data[ip]["last"] = time()


        except Exception as err:
            self.error = err







# === Request === #
class Request(Thread):
    def __init__(self):
        super().__init__()

        self.s = socket(AF_PACKET, SOCK_RAW, htons(0x0806))
        self.s.bind((args.interface, htons(0x0806)))

        self.pps = 0
        self.current = ""
        self.running = True
        self.error = ""


    def terminate(self):
        self.running = False


    def run(self):
        try:
            t = time()
            while self.running:
                for ip in ip_range(args.range):
                    if not self.running: break
                    self.pps = round( 1/(time()-t), 2)
                    t = time()

                    ip = str(ip)
                    self.current = ip

                    srcip = "{}.{}.{}.1".format( *ip.split(".")[:3] )
                    self.fake = srcip

                    src = (srcip, 0, args.mac)
                    dst = (ip, 0, "FF:FF:FF:FF:FF:FF")

                    arp, eth = ARP(), ETHERNET()
                    arp.build( src=src, dst=dst )
                    eth.build( src=src, dst=dst, protocol=0x0806, data=arp.packet)

                    self.s.send(eth.packet)

                    sleep(args.delay)

                self.current = "finished scan"
                if not args.repeat: break


        except Exception as err:
            self.error = err







# === Display === #
class Display(Screen):
    def __init__(self):
        super().__init__()

        self.head = { "bg":(225,225,225), "fg":(150,150,150), "bold":1 }
        self.head_italic = { "bg":(225,225,225), "fg":(150,150,150), "bold":1, "italic":1 }
        self.mode = { "bg":(225,225,225), "fg":(100,100,100), "bold":1, "italic":1 }
        self.title = { "bg":(150,150,150), "fg":(50,50,50), "bold":1, "underline":1}
        self.info = { "bg": (50, 50, 50), "fg": (150, 150, 150) }
        self.warning = { "fg":(255,0,0), "bold":1 }

        self.error = ""


    def update(self):
        try:
            self.terminalsize()
            self.clear()
            cursor.hide()

            data = analyse.data.copy()

            self.write( " "*self.w, r=1, opt=self.head )

            self.write( "MONITARP  -  c0mplh4cks", r=1, c=2, opt=self.head )

            if args.timeout:
                self.write( "timeout", r=1, c=self.w-50, opt=self.mode)
            if args.limit:
                self.write( "limited", r=1, c=self.w-40, opt=self.mode)
            if args.stealth:
                self.write( "stealth", r=1, c=self.w-30, opt=self.mode)
            if "ip" not in args.blur:
                self.write( args.range, r=1, c=self.w-20, opt=self.head_italic)

            c = 3
            self.write( " IP ", r=4, c=c+1, opt=self.title )
            self.write( " MAC ", r=4, c=c+24, opt=self.title )
            self.write( " VENDOR ", r=4, c=c+48, opt=self.title )
            self.write( " DYNAMIC ", r=4, c=c+92, opt=self.title )
            if args.verbose:
                self.write(" FIRST ", r=4, c=c+108, opt=self.title)
                self.write(" LAST ", r=4, c=c+124, opt=self.title)

            r = 6
            for i, ip in enumerate(data):
                if (r+i) > self.h-2: break

                if "ip" not in args.blur:
                    self.write( ip, r=r+i, c=c+1, opt=self.info )
                if "mac" not in args.blur:
                    self.write( data[ip]["mac"], r=r+i, c=c+24, opt=self.info )
                if "vendor" not in args.blur:
                    self.write( data[ip]["vendor"], r=r+i, c=c+48, opt=self.info )
                if "dynamic" not in args.blur:
                    self.write( data[ip]["dynamic"], r=r+i, c=c+92, opt=self.info )
                if args.verbose:
                    if "first" not in args.blur:
                        self.write( strftime("%H:%M:%S", gmtime(data[ip]["first"])), r=r+i, c=c+108, opt=self.info )
                    last = time() - data[ip]["last"]
                    if "last" not in args.blur:
                        self.write( strftime("%M:%S", gmtime(last)), r=r+i, c=c+124, opt=self.info)

            self.write( " "*self.w, r=self.h, opt=self.head )

            if args.verbose:
                self.write( "device(s)", r=self.h, c=self.w-20, opt=self.head )
                self.write( len(data), r=self.h, c=self.w-10, opt=self.head_italic )

                if not args.stealth:
                    self.write( "pckts/s", r=self.h, c=self.w-36, opt=self.head )
                    self.write( request.pps, r=self.h, c=self.w-28, opt=self.head_italic )

                if "ip" not in args.blur:
                    self.write( request.current, r=self.h, c=self.w-52, opt=self.head_italic)
                if "mac" not in args.blur:
                    self.write( args.mac, r=self.h, c=2, opt=self.head_italic)
                if "interface" not in args.blur:
                    self.write( args.interface, r=self.h, c=23, opt=self.head_italic)


        except Exception as err:
            self.error = err








# === Main === #
if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument( "-s", "--stealth", help="stealth mode", action="store_true" )
    parser.add_argument( "-o", "--output", help="output file", default=False )
    parser.add_argument( "-L", "--log", help="log file", default=False )
    parser.add_argument( "-r", "--range", help="IP scan range", default="192.168.0.0/16" )
    parser.add_argument( "-i", "--interface", help="networking interface", default="wlan0" )
    parser.add_argument( "-d", "--delay", help="delay between requests", default=0.1, type=float )
    parser.add_argument( "-m", "--mac", help="MAC address used in requests", default="00:00:00:00:00:00" )
    parser.add_argument( "-l", "--limit", help="limit ARP packets to be accepted as valid info", action="store_true" )
    parser.add_argument( "-v", "--verbose", help="show more details", action="store_true" )
    parser.add_argument( "-R", "--repeat", help=" stop repeating IP scan", action="store_false" )
    parser.add_argument( "-t", "--timeout", help="remove from gui when timeout", default=0, type=int)
    parser.add_argument( "-b", "--blur", help="blur data", action="append" )
    parser.add_argument( "--nogui", help="no graphical user interface", action="store_true" )

    args = parser.parse_args()

    if args.blur == None:
        args.blur = []


    error = ""

    monitor = Monitor()
    request = Request()
    display = Display()
    analyse = Analyse()
    output = Output()
    log = Log()
    if not args.nogui:
        display.clean()

    monitor.start()
    analyse.start()
    if not args.stealth:
        request.start()
    if args.output:
        output.start()
    if args.log:
        log.start()

    try:
        cursor.hide()
        if not args.nogui: print( text(" MONITARP  -  c0mplh4cks ", **display.head, blink=1) )
        sleep(2)

        while not error:
            if monitor.error:
                error = f"Error in Monitor:\n { str(monitor.error) }"
            if request.error:
                error = f"Error in Request:\n { str(request.error) }"
            if display.error:
                error = f"Error in Display:\n { str(display.error) }"
            if analyse.error:
                error = f"Error in Analyse:\n { str(analyse.error) }"
            if output.error:
                error = f"Error in Output:\n { str(log.error) }"
            if log.error:
                error = f"Error in Log:\n { str(log.error) }"


            if not args.nogui:
                display.update()
            sleep(0.5)


    except KeyboardInterrupt:
        error = "Executed user's request to kill the program..."


    finally:
        monitor.terminate()
        request.terminate()
        analyse.terminate()
        output.terminate()
        log.terminate()

        cursor.show()

        if args.output:
            output.outputfile()
            print( text(" output written to file...", **display.warning) )


        print()
        print( f" {text(str(error), **display.warning)}\n " )
        print()
