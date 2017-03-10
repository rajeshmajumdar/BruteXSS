#! /usr/bin/env python

__author__ = 'Rajesh Majumdar'
__version__ = '1.5'

try:
    from tkinter import *
    import tkinter.scrolledtext as sctx
except:
    from Tkinter import *
    import ScrolledText as sctx


try:
    import ttk
except ImportError:
    from tkinter.ttk import ttk

import sys
import os
import urlparse
from string import whitespace
import urllib
import httplib
import thread
import time
import tkMessageBox
import threading
from time import gmtime, strftime
import urllib2
import webbrowser

from wordlistimport import importword
from checkurl import checkurl
from parameters import checkparams, getquery
import mechanize

brutexss = urllib2.urlopen('https://raw.githubusercontent.com/rajeshmajumdar/BruteXSS/master/brutexss.txt').read()

def mainbody():

    top = Tk()

    _bgcolor = '#d9d9d9'  # X11 color: 'gray85'
    _fgcolor = '#000000'  # X11 color: 'black'
    _compcolor = '#d9d9d9' # X11 color: 'gray85'
    _ana1color = '#d9d9d9' # X11 color: 'gray85'
    _ana2color = '#d9d9d9' # X11 color: 'gray85'
    style = ttk.Style()
    if sys.platform == "win32":
        style.theme_use('winnative')
    style.configure('.',background=_bgcolor)
    style.configure('.',foreground=_fgcolor)
    style.configure('.',font="TkDefaultFont")
    style.map('.',background=
                [('selected', _compcolor), ('active',_ana2color)])

    top.geometry("598x537+442+151")
    top.title("BruteXSS - XSS Bruteforcing Tool")
    top.configure(background="#d9d9d9")
    top.configure(highlightbackground="#d9d9d9")
    top.configure(highlightcolor="black")
    
    
    #if os.name == "nt":
     #   top.iconbitmap('icon.ico')
    #else:
     #   pass

    def getmethod(vlink):
        #print "Program reached here"
        path = "wordlist.txt"
        site = vlink
        if 'https://' in vlink:
            pass
        elif 'http://' in vlink:
            pass
        else:
            #print "Program is there"
            site = 'http://'+vlink
        finalurl= urlparse.urlparse(site)
        urldata = urlparse.parse_qsl(finalurl.query)
        domain0 = '{uri.scheme}://{uri.netloc}/'.format(uri=finalurl)
        domain = domain0.replace("https://","").replace("http://","").replace("www.","").replace("/","")
        #print (Style.DIM+Fore.WHITE+"[+] Checking if "+domain+" is available..."+Style.RESET_ALL)
        #connection = httplib.HTTPConnection(domain)
        #connection.connect()
        #print("[+] "+Fore.GREEN+domain+" is available! Good!"+Style.RESET_ALL)
        url = site
        paraname = []
        paravalue = []
        payloads = []
        importword(path,payloads)
        #print payloads
        lop = str(len(payloads))
        output.insert(END, "\n[+] "+lop+" payloads loaded.")
        output.insert(END, "\n[+] Bruteforce start:")
        o = urlparse.urlparse(site)
        parameters = urlparse.parse_qs(o.query,keep_blank_values=True)
        path = urlparse.urlparse(site).scheme+"://"+urlparse.urlparse(site).netloc+urlparse.urlparse(site).path
        for para in parameters:
            for i in parameters[para]:
                paraname.append(para)
                paravalue.append(i)
        total = 0
        c = 0
        fpar = []
        fresult = []
        prgs = 0
        for pn, pv in zip(paraname,paravalue): #Scanning the parameter.
                output.insert(END, "\n[+] Testing '"+pn+"' parameter...")
                fpar.append(str(pn))
                for x in payloads: #
                    validate = x.translate(None, whitespace)
                    if validate == "":

                        prgs = prgs + 1
                    else:
                        output.insert(END, "\n[+] %i / %s payloads injected..."% (prgs,len(payloads)))
                        prgs = prgs + 1
                        enc = urllib.quote_plus(x)
                        data = path+"?"+pn+"="+pv+enc
                        page = urllib.urlopen(data)
                        sourcecode = page.read()
                        if x in sourcecode:
                                output.insert(END, "\n[!]"+" XSS Vulnerability Found! \n[!]"+" Parameter:\t"+pn+"\n[!] Payload:\t"+x)
                                fresult.append("  Vulnerable  ")
                                c = 1
                    total = total+1
                else:
                    c = 0
        if c == 0:
            output.insert(END, "\n[+] '"+pn+"' parameter not vulnerable.")
            fresult.append("Not Vulnerable")
            prgs = prgs + 1
            pass
        prgs = 0
        complete(fpar,fresult,total,domain)
    def complete(p, r, c, d):
            output.insert(END, "\n[+] Bruteforcing Completed.")
            progress.stop()
            if c == 0:
                output.insert(END, "\n[+] Given parameters are not vulnerable.")
            elif c == 1:
                output.insert(END, "\n[+] 0 parameters are vulnerable to XSS.")
            else:
                output.insert(END, "\n[+] %s Parameters are vulnerable to XSS."%c)

    def postmethod(vlink):
        br = mechanize.Browser()
        br.addheaders = [('User-agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11)Gecko/20071127 Firefox/2.0.0.11')]
        br.set_handle_robots(False)
        br.set_handle_refresh(False)
        site = vlink
        if 'https://' in site:
            pass
        elif 'http://' in site:
            pass
        else:
            site = 'http://'+site
        finalurl = urlparse.urlparse(site)
        urldata = urlparse.parse_qsl(finalurl.query)
        domain0 = '{uri.scheme}://{uri.netloc}/'.format(uri=finalurl)
        domain = domain0.replace("https://","").replace("http://","").replace("www.","").replace("/","")
        path = urlparse.urlparse(site).scheme+"://"+urlparse.urlparse(site).netloc+urlparse.urlparse(site).path
        url = site
        with open ('postdata.txt', 'r') as f:
            param = f.read()
        wrdlist = wordlist.get()
        payloads = []
        importword(wrdlist,payloads)
        lop = str(len(payloads))
        output.insert(END, "[+] "+lop+" Payloads loaded...")
        output.insert(END, "[+] Bruteforce start:")
        params = "http://www.site.com/?"+param
        finalurl = urlparse.urlparse(params)
        urldata = urlparse.parse_qsl(finalurl.query)
        o = urlparse.urlparse(params)
        parameters = urlparse.parse_qs(o.query,keep_blank_values=True)
        paraname = []
        paravalue = []
        for para in parameters: #Arranging parameters and values.
            for i in parameters[para]:
                paraname.append(para)
                paravalue.append(i)
        fpar = []
        fresult = []
        total = 0
        prgs = 0
        pname1 = [] #parameter name
        payload1 = []
        for pn, pv in zip(paraname,paravalue): #Scanning the parameter.
            output.insert(END, "[+] Testing '"+pn+"' parameter...")
            fpar.append(str(pn))
            for i in payloads:
                validate = i.translate(None, whitespace)
                if validate == "":
                    progress = progress + 1
                else:
                    progress = progress + 1
                    output.insert(END, "\n[+] %i / %s payloads injected..."% (prgs,len(payloads)))
                    pname1.append(pn)
                    payload1.append(str(i))
                    freakym0nk = 0
                    for m in range(len(paraname)):
                        d = paraname[freakym0nk]
                        d1 = paravalue[freakym0nk]
                        tst= "".join(pname1)
                        tst1 = "".join(d)
                        if pn in d:
                            freakym0nk = freakym0nk + 1
                        else:
                            freakym0nk = freakym0nk +1
                            pname1.append(str(d))
                            payload1.append(str(d1))
                    data = urllib.urlencode(dict(zip(pname1,payload1)))
                    r = br.open(path, data)
                    sourcecode =  r.read()
                    pname1 = []
                    payload1 = []
                    if i in sourcecode:
                        output.insert(END, "\n[!]   "+" XSS Vulnerability Found! \n[!]   "+" Parameter:\t%s\n[!]  "+" Payload:\t%s")%(pn,i)
                        fresult.append("  Vulnerable  ")
                        c = 1
                        total = total+1
                    else:
                        c = 0
            if c == 0:
                output.insert(END, "\n[+]"+" '%s' parameter not vulnerable.")%pn
                fresult.append("Not Vulnerable")
                prgs = prgs + 1
                pass
            prgs = 0
        complete(fpar,fresult,total,domain)
    def execute():
        time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        output.insert(END, "\nBruteXSS started on "+time)
        status = "0"
        link = url.get()            #Working for URL
        postchecked = postmethodchecked.get()
        getchecked = getmethodchecked.get()
        #print link                  #For Testing
        domainame = urlparse.urlparse(link)
        domainname = domainame.hostname

        #Checking for URL
        isavailable = checkurl(link, status)
        if isavailable == "1":
            output.insert(END, "\n\n[+] Site '"+domainname+"' is available, Good!")
        else:
            output.insert(END, "\n[!] Oops! URL not available")

        #Checking for params
        param = checkparams(link)
        #print param            #For testing
        if param == "1":
            print("\nParam is there.")
        elif param == "0":
            output.insert(END, "\n[!] Oops! can't find any parameters!")
            output.insert(END, "\nPlease try again.")
            top.mainloop()
        #else:
            #output.insert(END, "\n Something went wrong.")

        #POST Data
        datafile = open("postdata.txt","w")
        content = postdata.get("1.0", "end-1c")
        datafile.write(content)
        datafile.close()


           #Working for path
        #print path                  #For testing
        #importword(path, payloads)
        #lop = str(len(payloads))
        #output.insert(END, "\n[+] Loading payloads....")
        #output.insert(END, "\n[+] Loaded "+lop+" payloads.")
        #progress.start(1)


        #The bruteforce part
        if postchecked == '1':
            postmethod(link)
        else:
            getmethod(link)
            
    def process():
        progress.start(1)
        bckprocess = threading.Thread(target=execute)
        bckprocess.start()

         #URL Field
    url = Entry(top)
    url.place(relx=0.22, rely=0.04, relheight=0.04, relwidth=0.49)
    url.configure(background="white")
    url.configure(disabledforeground="#a3a3a3")
    url.configure(font="TkFixedFont")
    url.configure(foreground="#000000")
    url.configure(highlightbackground="#d9d9d9")
    url.configure(highlightcolor="black")
    url.configure(insertbackground="black")
    url.configure(selectbackground="#c4c4c4")
    url.configure(selectforeground="black")
    url.insert(END, "https://")

        #BruteXSS Button
    brutexss = Button(top, command=process)       #Remove ""
    brutexss.place(relx=0.75, rely=0.04, height=25, width=76)
    brutexss.configure(activebackground="#d9d9d9")
    brutexss.configure(activeforeground="#000000")
    brutexss.configure(background="#d9d9d9")
    brutexss.configure(disabledforeground="#a3a3a3")
    brutexss.configure(foreground="#000000")
    brutexss.configure(highlightbackground="#d9d9d9")
    brutexss.configure(highlightcolor="black")
    brutexss.configure(pady="0")
    brutexss.configure(text='''BruteXSS''')

    #Label 1
    TLabel1 = ttk.Label(top)
    TLabel1.place(relx=0.1, rely=0.04, height=19, width=66)
    TLabel1.configure(background="#d9d9d9")
    TLabel1.configure(foreground="#000000")
    TLabel1.configure(relief=FLAT)
    TLabel1.configure(text='''Enter URL''')

    #Progress Bar
    progress = ttk.Progressbar(top, orient = HORIZONTAL, length=395, mode="indeterminate")
    progress.place(relx=0.07, rely=0.17, relwidth=0.85
                    , relheight=0.0, height=22)

    #Label 2
    TLabel2 = ttk.Label(top)
    TLabel2.place(relx=0.18, rely=0.95, height=19, width=154)
    TLabel2.configure(background="#d9d9d9")
    TLabel2.configure(foreground="#000000")
    TLabel2.configure(relief=FLAT)
    TLabel2.configure(text='''CLI Developer : Shawar Khan''')

    #Label 3
    TLabel3 = ttk.Label(top)
    TLabel3.place(relx=0.48, rely=0.95, height=19, width=180)
    TLabel3.configure(background="#d9d9d9")
    TLabel3.configure(foreground="#000000")
    TLabel3.configure(relief=FLAT)
    TLabel3.configure(text='''GUI Developer : Rajesh Majumdar''')

    #MenuBar
    menubar = Menu(top,bg=_bgcolor,fg=_fgcolor)
    top.configure(menu = menubar)

    #Label 4
    TLabel4 = ttk.Label(top)
    TLabel4.place(relx=0.07, rely=0.3, height=19, width=90)
    TLabel4.configure(background="#d9d9d9")
    TLabel4.configure(foreground="#000000")
    TLabel4.configure(relief=FLAT)
    TLabel4.configure(text='''Enter POST Data''')

    #Label 5
    TLabel5 = ttk.Label(top)
    TLabel5.place(relx=0.07, rely=0.54, height=19, width=42)
    TLabel5.configure(background="#d9d9d9")
    TLabel5.configure(foreground="#000000")
    TLabel5.configure(relief=FLAT)
    TLabel5.configure(text='''Output''')
    
    #Label 6
    TLabel6 = ttk.Label(top)
    TLabel6.place(relx=0.07, rely=0.24, height=19, width=91)
    TLabel6.configure(background="#d9d9d9")
    TLabel6.configure(foreground="#000000")
    TLabel6.configure(relief=FLAT)
    TLabel6.configure(text='''Custom wordlist''')

    #Wordlist Path
    wordlist = Entry(top)                   #WORDLIST HERE
    wordlist.place(relx=0.25, rely=0.24, relheight=0.04, relwidth=0.65)
    wordlist.configure(background="white")
    wordlist.configure(disabledforeground="#a3a3a3")
    wordlist.configure(font="TkFixedFont")
    wordlist.configure(foreground="#000000")
    wordlist.configure(highlightbackground="#d9d9d9")
    wordlist.configure(highlightcolor="black")
    wordlist.configure(insertbackground="black")
    wordlist.configure(selectbackground="#c4c4c4")
    wordlist.configure(selectforeground="black")
    wordlist.insert(END, "wordlist.txt")

    #POST Data Box
    postdata = sctx.ScrolledText(top)
    postdata.place(relx=0.07, rely=0.34, relheight=0.21
                    , relwidth=0.84)
    postdata.configure(background="white")
    postdata.configure(font="TkTextFont")
    postdata.configure(foreground="black")
    postdata.configure(highlightbackground="#d9d9d9")
    postdata.configure(highlightcolor="black")
    postdata.configure(insertbackground="black")
    postdata.configure(insertborderwidth="3")
    postdata.configure(selectbackground="#c4c4c4")
    postdata.configure(selectforeground="black")
    postdata.configure(width=10)
    postdata.configure(wrap=NONE)

    #Output Box
    output = sctx.ScrolledText(top)
    output.place(relx=0.07, rely=0.58, relheight=0.36
                    , relwidth=0.84)
    output.configure(background="white")
    output.configure(font="TkTextFont")
    output.configure(foreground="black")
    output.configure(highlightbackground="#d9d9d9")
    output.configure(highlightcolor="black")
    output.configure(insertbackground="black")
    output.configure(insertborderwidth="3")
    output.configure(selectbackground="#c4c4c4")
    output.configure(selectforeground="black")
    output.configure(width=10)
    output.configure(wrap=NONE)
    output.see(END)

    #GET Method Checkbox
    getmethodchecked = IntVar()
    getmethodchecked.set(1)
    getmethodcheck = Checkbutton(top, variable=getmethodchecked)
    getmethodcheck.place(relx=0.25, rely=0.11, relwidth=0.15
                    , relheight=0.0, height=21)
    getmethodcheck.configure(activebackground="#d9d9d9")
    getmethodcheck.configure(activeforeground="#000000")
    getmethodcheck.configure(background="#d9d9d9")
    getmethodcheck.configure(disabledforeground="#a3a3a3")
    getmethodcheck.configure(foreground="#000000")
    getmethodcheck.configure(highlightbackground="#d9d9d9")
    getmethodcheck.configure(highlightcolor="black")
    getmethodcheck.configure(justify=LEFT)
    getmethodcheck.configure(text='''GET Method''')

    #POST Method Check
    postmethodchecked = IntVar()
    postmethodcheck = Checkbutton(top, variable=postmethodchecked)
    postmethodcheck.place(relx=0.52, rely=0.11, relwidth=0.16
                    , relheight=0.0, height=21)
    postmethodcheck.configure(activebackground="#d9d9d9")
    postmethodcheck.configure(activeforeground="#000000")
    postmethodcheck.configure(background="#d9d9d9")
    postmethodcheck.configure(disabledforeground="#a3a3a3")
    postmethodcheck.configure(foreground="#000000")
    postmethodcheck.configure(highlightbackground="#d9d9d9")
    postmethodcheck.configure(highlightcolor="black")
    postmethodcheck.configure(justify=LEFT)
    postmethodcheck.configure(text='''POST Method''')

    top.mainloop()


def checkupdates():
    def errorbox():
        error = Tk()
        error.geometry("268x82+482+242")
        error.title("Error!")
        error.configure(background="#d9d9d9")
        if os.name == 'nt':
            error.iconbitmap('icon.ico')
        else:
            pass

        Label1 = Label(error)
        Label1.place(relx=0.04, rely=0.24, height=21, width=244)
        Label1.configure(background="#d9d9d9")
        Label1.configure(disabledforeground="#a3a3a3")
        Label1.configure(foreground="#000000")
        Label1.configure(text='''Oops! I think you''')
        Label1.configure(width=244)

        Label2 = Label(error)
        Label2.place(relx=0.07, rely=0.49, height=21, width=230)
        Label2.configure(background="#d9d9d9")
        Label2.configure(disabledforeground="#a3a3a3")
        Label2.configure(foreground="#000000")
        Label2.configure(text='''don't have a working internet connection !''')
        
        error.mainloop()
        
    try:
        versionfile = urllib2.urlopen('https://raw.githubusercontent.com/rajeshmajumdar/BruteXSS/master/version.txt').read()
        if float(versionfile) > float(__version__):
            updatefunc()
        else:
            print 'Nothing happened'
            start()
    except Exception as e:
        errorbox()

def updatefunc():

    update = Tk()

    update.geometry("270x192+454+143")
    update.title("Software Update")
    update.configure(background='#d9d9d9')
    if os.name == 'nt':
        update.iconbitmap('icon.ico')
    else:
        pass

    def yes():
        if os.name == 'nt':
            webbrowser.open_new_tab('https://github.com/rajeshmajumdar/BruteXSS/archive/master.zip')
            update.destroy()
        else:
            os.system('git clone https://github.com/rajeshmajumdar/BruteXSS.git')
            update.destroy()
    def no():
        print 'This thing is also working.'
        update.destroy()
        start()

    Label1 = Label(update)
    Label1.place(relx=0.07, rely=0.1, height=21, width=224)
    Label1.configure(background="#d9d9d9")
    Label1.configure(disabledforeground="#a3a3a3")
    Label1.configure(foreground="#000000")
    Label1.configure(text='''BruteXSS got a new update !''')
    Label1.configure(width=224)

    Button1 = Button(update, command=yes)
    Button1.place(relx=0.19, rely=0.57, height=24, width=69)
    Button1.configure(activebackground="#d9d9d9")
    Button1.configure(activeforeground="#000000")
    Button1.configure(background="#d9d9d9")
    Button1.configure(disabledforeground="#a3a3a3")
    Button1.configure(foreground="#000000")
    Button1.configure(highlightbackground="#d9d9d9")
    Button1.configure(highlightcolor="black")
    Button1.configure(pady="0")
    Button1.configure(text='''Yes''')
    Button1.configure(width=69)

    Button2 = Button(update, command=no)
    Button2.place(relx=0.52, rely=0.57, height=24, width=67)
    Button2.configure(activebackground="#d9d9d9")
    Button2.configure(activeforeground="#000000")
    Button2.configure(background="#d9d9d9")
    Button2.configure(disabledforeground="#a3a3a3")
    Button2.configure(foreground="#000000")
    Button2.configure(highlightbackground="#d9d9d9")
    Button2.configure(highlightcolor="black")
    Button2.configure(pady="0")
    Button2.configure(text='''No''')
    Button2.configure(width=67)

    Label2 = Label(update)
    Label2.place(relx=0.07, rely=0.31, height=21, width=213)
    Label2.configure(background="#d9d9d9")
    Label2.configure(disabledforeground="#a3a3a3")
    Label2.configure(foreground="#000000")
    Label2.configure(text='''Do you want to download this update ?''')

    update.mainloop()


def start():
    start = Tk()
    start.geometry("1x1+"+str(start.winfo_screenwidth()/2)+"+"+str(start.winfo_screenheight()/2))
    tkMessageBox.showinfo(title="Disclaimer", message="This tool is a free software.\nIt means you are not allowed to modify the source code, or any files of this tool, or not allowed to sell its copy.\nYou can use this tool in your tool but you are not allowed to modify anything.")
    mainbody()

if __author__ == 'Rajesh Majumdar':
    checkupdates()
else:
    print "Noob! Don't try to modify the code."
