""" 
This Is Packet Sniffer with filteration capabilities
"""

from tkinter import *
from tkinter import filedialog,ttk,messagebox
import socket,struct,textwrap,binascii


#==========================================================================================================================================================================================================================================
#============================= Backend Part ===============================================================================================================================================================================================
#==========================================================================================================================================================================================================================================

#global var fro stoping and filtering the packets
global_stop=0
fl=0
ver='1.0.4'


#---------creating the connection------------------------------------------------------------------------------------------------
conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))

#actual fuction to view the resulting packets on the text wigdet of the GUI-------------------------------------------------------
def view_result():
        raw_data,addr=conn.recvfrom(65565)
        dest_mac,src_mac,eth_proto,data=ethernet_frame(raw_data)
        #l1.insert(END,('\n Ethernet Frame:\n\t -Destination: %s, Source: %s, Protocol: %d'%(dest_mac,src_mac,eth_proto)))
        #l1.yview(END)

        #2048 forIPv4
        if eth_proto==2048 and (fl*1==1 or fl*1==6 or fl*1==17 or fl*1 == 0):
                (version,header_length,ttl,proto,src,target,data)=ipv4_packet(data)
                #l1.insert(END,'\n\t - IPv4 Packet:\n\t\t - Version: %s, Header Length: %d, TTL: %d\n \t\t - Protocol: %d, Source: %s, Target: %s'%(version,header_length,ttl,proto,src,target))
                #l1.yview(END)

                #ICMP
                if proto == 1 and (fl*1==1 or fl*1 == 0):
                        l1.insert(END,('\n Ethernet Frame:\n\t -Destination: %s, Source: %s, Protocol: %d'%(dest_mac,src_mac,eth_proto)))
                        l1.yview(END)
                        l1.insert(END,'\n\t - IPv4 Packet:\n\t\t - Version: %s, Header Length: %d, TTL: %d\n \t\t - Protocol: %d, Source: %s, Target: %s'%(version,header_length,ttl,proto,src,target))
                        l1.yview(END)
                        icmp_type,code,checksum,data=icmp_packets(data)
                        l1.insert(END,'\n\t -  ICMP Packet:\n\t\t - Type: %d, Code: %d,Checksum: %d,\n'%(icmp_type,code,checksum))
                        l1.insert(END,format_multi_line('\t\t\t ',data))
                        l1.yview(END)

                #TCP
                elif proto == 6 and (fl*1==6 or fl*1 == 0):
                        l1.insert(END,('\n Ethernet Frame:\n\t -Destination: %s, Source: %s, Protocol: %d'%(dest_mac,src_mac,eth_proto)))
                        l1.yview(END)
                        l1.insert(END,'\n\t - IPv4 Packet:\n\t\t - Version: %s, Header Length: %d, TTL: %d\n \t\t - Protocol: %d, Source: %s, Target: %s'%(version,header_length,ttl,proto,src,target))
                        l1.yview(END)
                        (src_port,dest_port,sequence,ack,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data)=tcp_segment(data)
                        l1.insert(END,'\n\t - TCP Segment:\n\t\t - Source Port: %d, Destination Port: %d\n\t\t - Sequence: %d, Acknowledgment: %d\n\t\t - Flags\n\t\t - URG: %d, ACK: %d, PSH: %d, RST: %d, SYN: %d, FIN:%d\n\t\t - Data: \n'%(src_port,dest_port,sequence,ack,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin))
                        l1.insert(END,format_multi_line('\t\t\t ',data))
                        l1.yview(END)

                #UDP
                elif proto == 17 and (fl*1==17 or fl*1 == 0):
                        l1.insert(END,('\n Ethernet Frame:\n\t -Destination: %s, Source: %s, Protocol: %d'%(dest_mac,src_mac,eth_proto)))
                        l1.yview(END)
                        l1.insert(END,'\n\t - IPv4 Packet:\n\t\t - Version: %s, Header Length: %d, TTL: %d\n \t\t - Protocol: %d, Source: %s, Target: %s'%(version,header_length,ttl,proto,src,target))
                        l1.yview(END)
                        src_port,dest_port,length,data=udp_segment(data)
                        l1.insert(END,'\n\t - UDP Segment:\n\t\t - Source Port: %d,Destination Port: %d, Length %d\n\t\t - Data: \n'%(src_port,dest_port,length))
                        l1.insert(END,format_multi_line('\t\t\t ',data))
                        l1.yview(END)

                #other
                #else:
                #        l1.insert(END,'\n\t - IPv4 Packet:\n\t\t - Version: %s, Header Length: %d, TTL: %d\n \t\t - Protocol: %d, Source: %s, Target: %s'%(version,header_length,ttl,proto,src,target))
                #        l1.yview(END)
                #        l1.insert(END,'\n\t - Data x:\n')
                #        l1.insert(END,format_multi_line('\t\t ',data))
                #        l1.yview(END)

        #for Arp Packets
        elif eth_proto==2054 and (fl*1==2054 or fl*1 == 0):
                l1.insert(END,('\n Ethernet Frame:\n\t -Destination: %s, Source: %s, Protocol: %d'%(dest_mac,src_mac,eth_proto)))
                l1.yview(END)
                (hw_type,proto_type,hw_size,proto_size,opcode,src_ip,dest_ip)=arp_header(raw_data)
                l1.insert(END,'\n\t - Arp Packet:\n\t\t - H/W Type: %s, Protocol Type: %s, H/W Size: %s ,Protocol Size: %s\n\t\t - Opcode: %s, Source IP: %s, Destination IP: %s'%(hw_type,proto_type,hw_size,proto_size,opcode,src_ip,dest_ip))
                l1.yview(END)

        #some other layer 3 protocols which are unparsed
        #else:
        #        l1.insert(END,'\nData EX:\n')
        #        l1.insert(END,format_multi_line('\t ',data))
        #        l1.yview(END)

        if global_stop==0:
                l1.after(400,view_result)
        #the above will loop the function similar funtioning to while loop---------------------------------


#unpack ethernet frame-------------------------------------------------------------------
def ethernet_frame(data):
    dest_mac,src_mac,proto=struct.unpack("6s6sH",data[:14])
    return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto),data[14:]


#Return properly formatted Mac Address(Ie AA:BB:CC:DD:EE:FF)------------------------------
def get_mac_addr(bytes_addr):
    bytes_str=map('{:02x}'.format,bytes_addr)
    return ':'.join(bytes_str).upper()

#unpack IPv4 packet-----------------------------------------------------------------------
def ipv4_packet(data):
    version_header_length=data[0]
    version=version_header_length >> 4
    header_length=(version_header_length & 15)*4
    ttl,proto,src,target=struct.unpack('!8x B B 2x 4s 4s',data[:20])
    return version,header_length,ttl,proto,ipv4(src),ipv4(target),data[header_length:]



#returns fromatted IPv4 Address-----------------------------------------------------------
def ipv4(addr):
    return '.'.join(map(str,addr))

#unpackes ICMP Packets---------------------------------------------------------------------
def icmp_packets(data):
     icmp_type,code,checksum=struct.unpack('!BBH',data[:4])
     return icmp_type,code,checksum,data[4:]
 


#unpackes tcp segment-----------------------------------------------------------------------
def tcp_segment(data):
        (src_port,dest_port,sequence,ack,offset_reserved_flags)=struct.unpack('!HHLLH',data[:14]) 
        offset=(offset_reserved_flags>>12)*4
        flag_urg=(offset_reserved_flags & 32)>>5
        flag_ack=(offset_reserved_flags & 16)>>4
        flag_psh=(offset_reserved_flags & 8)>>3
        flag_rst=(offset_reserved_flags & 4)>>2
        flag_syn=(offset_reserved_flags & 2)>>1
        flag_fin=offset_reserved_flags & 1        
        return src_port,dest_port,sequence,ack,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data[offset:]



#unpacks UDP segment-------------------------------------------------------------------------------------
def udp_segment(data):
        src_port,dest_port,size=struct.unpack('H H 2x H',data[:8])
        return src_port,dest_port,size,data[8:]


#formats multiline data----------------------------------------------------------------------------------
def format_multi_line(prefix,string,size=80):
        size-=len(prefix)
        if isinstance(string,bytes):
                string=''.join(r'\x{:02x}'.format(byte) for byte in string)
                if size%2:
                        size-=1
        return '\n'.join([prefix+line for line in textwrap.wrap(string,size)])

#Disect the arp header and returning the content in str---------------------------------------------------
def arp_header(data):
	#(raw_data[14:42]) -gives byte hex literals
	#hexlify gives out byte object which need to parse be decode utf-8
	(hw_type,proto_type,hw_size,proto_size,opcode,src_mac,src_ip,dest_mac,dest_ip)=struct.unpack('2s2s1s1s2s6s4s6s4s',data[14:42])

	hw_type=(binascii.hexlify(hw_type)).decode('utf-8')
	proto_type=(binascii.hexlify(proto_type)).decode('utf-8')
	hw_size=(binascii.hexlify(hw_size)).decode('utf-8')
	proto_size=(binascii.hexlify(proto_size)).decode('utf-8')
	opcode=(binascii.hexlify(opcode)).decode('utf-8')

	return (hw_type,proto_type,hw_size,proto_size,opcode,socket.inet_ntoa(src_ip),socket.inet_ntoa(dest_ip))



#======================================================================================================================================================================================================================
#=========================================Front End Maupulation functions===============================================================================================================================================
#======================================================================================================================================================================================================================

#Clear the text area and reset the filter value---------------------------------------------------------------
def reset_view():
    l1.delete('1.0',END)
    global fl
    fl=0

#stops the real time feed of packet caputuring without clearing the text area--------------------------------
def stop_view():
        global global_stop
        global_stop=1
        status=Label(root,text="  Ready to Capture.....",width=174,bd=1,relief=SUNKEN,anchor=W)
        status.grid(row=13,columnspan=20,sticky=W)

#intiator fuction for viewing result functon of above--------------------------------------------------------
def start_view():
        global global_stop
        global_stop=0
        status=Label(root,text="  Capturing......",width=174,bd=1,relief=SUNKEN,anchor=W)
        status.grid(row=13,columnspan=20,sticky=W)
        #progressbar inderterminate
        p = ttk.Progressbar(root, orient=HORIZONTAL, length=300, mode='indeterminate' )
        p.grid(row=13,column=1,columnspan=18,sticky=W)
        p.start()
        view_result()

#defining the variable for filtering the packets----------------------------------------------------------------
def filter_view():
    l1.delete('1.0',END)
    global fl
    if filter_value.get() == 'all':
            fl=0
    if filter_value.get() == 'tcp':
            fl=6
    if filter_value.get() == 'icmp':
            fl=1
    if filter_value.get() == 'udp':
            fl=17
    if filter_value.get() == 'arp':
            fl=2054
    start_view()

def text_dump():
        thetext = l1.get('1.0', 'end')
        filename = filedialog.asksaveasfilename()
        with open(filename,'w+') as file1:
                file1.write(thetext)

def open_file():
        filename = filedialog.askopenfilename()
        if filename!="":
                with open(filename,'r') as file1:
                        l1.delete('1.0',END)
                        contents =file1.read()
                        l1.insert(END,contents)
                        l1.yview(END)

def about_me():
        msg="Developer:\n\tAman Gupta"
        messagebox.showinfo("About Us", msg)

def changelog():
        msg= "ver 1.0.4-\n\tMenusbar Fuctionality added\n\tprogressbar added\n\tBug Fixes\nver 1.0.3-\n\tAdded Menus\n\tArp Detection added\n\tBug Fixes\nver 1.0.2-\n\tPacket filteration added\n\tBug Fixes\nver 1.0.1-\n\tBeta Build"
        messagebox.showinfo("Changelog",msg)

def faq():
        msg="Filtering Options:\n\t1) tcp\n\t2) udp\n\t3) icmp\n\t4) arp\n\t5) all"
        messagebox.showinfo("FAQ",msg)   


#=======================================================================================================================================================================================================
#==========================GUI Implimentation===========================================================================================================================================================
#=======================================================================================================================================================================================================

root=Tk()
root.wm_title(("Easy Sniffer v %s"%ver))

#----------Menu Bar(TOP)-----------------------------------------------------
menubar=Menu(root)
root.config(menu=menubar)

file_menu=Menu(menubar,tearoff=0)
menubar.add_cascade(label="File",menu=file_menu)
file_menu.add_command(label='Open',command=open_file)
file_menu.add_command(label='Save',command=text_dump)
file_menu.add_separator()
file_menu.add_command(label='Exit',command=root.quit)

view_menu=Menu(menubar,tearoff=0)
menubar.add_cascade(label='View',menu=view_menu)
view_menu.add_command(label='Changelog',command=changelog)
view_menu.add_command(label='XYZ',command='')

help_menu=Menu(menubar,tearoff=0)
menubar.add_cascade(label="Help",menu=help_menu)
help_menu.add_command(label='FAQ',command=faq)
help_menu.add_command(label='About',command=about_me)

#----------Status Bar down-----------------------------------------------------------------------------------
status=Label(root,text="  Ready to Capture.....",width=174,bd=1,relief=SUNKEN,anchor=W)
status.grid(row=13,columnspan=20,sticky=W)




#----------row 1 buttons----------------------------------------------------------------------------------------
top_buttons=Frame(root)
top_buttons.grid(row=0)

b1=Button(top_buttons,text="Start",width=8,bg="#187f03",fg="white",command=start_view)
b1.grid(row=0,column=0)

b3=Button(top_buttons,text="Stop",width=9,bg="#a30101",fg="white",command=stop_view)
b3.grid(row=0,column=1)

b4=Button(root,text="Reset",width=8,bg="#686262",fg="white",command=reset_view)
b4.grid(row=0,column=1)

b5=Button(root,text="Save",width=8,bg="#686262",fg="white",command=text_dump)
b5.grid(row=0,column=2)



#-------------row 2 Buttons-------------------------------------------------------------
top_bu=Frame(root)
top_bu.grid(row=1)

b6=Button(top_bu,text="Filter",width=20,bg="#3b4047",fg="white",command=filter_view)
b6.grid(row=1,column=0,columnspan=2)
filter_value=StringVar()
e1=Entry(root,textvariable=filter_value,width=180)
e1.grid(row=1,column=2,columnspan=20)

#--------row 3 to row 13 listbox 1-----------------------------------------------------

l1=Text(root,height=34,width=180)
l1.grid(row=2,column=0,rowspan=10,columnspan=18)

sb1=Scrollbar(root)
sb1.grid(row=2,column=20,rowspan=10)
sb1.configure(command=l1.yview)


root.mainloop()
