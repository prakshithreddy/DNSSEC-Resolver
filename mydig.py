import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import dns.resolver
import sys
import time


localservers = ['130.245.255.4','207.244.82.25']

google_servers = ['8.8.8.8', '8.8.4.4']

rootservers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
               '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

#rootservers information obtained from "https://www.iana.org/domains/root/servers"

alexa_top25_websites = ['google.com', 'youtube.com', 'facebook.com', 'baidu.com', 'wikipedia.org', 'reddit.com', 'yahoo.com', 'google.co.in', 'Qq.com', 'Toabao.com', 'amazon.com',
            'Tmall.com', 'Twitter.com', 'google.co.jp', 'instagram.com', 'live.com', 'Vk.com', 'Sohu.com', 'Sina.com.cn', 'jd.com', 'Weibo.com', '360.cn',
            'google.de','google.co.uk', 'google.com.br']

#websites obtained from alexa.com

#print function is a modification of __str__ function of dnspython for message class.

def print_output(r, **kw):
    origin = None
    relativize = True
    print (u';QUESTION')
    for rrset in r.question:
        print (rrset.to_text(origin, relativize, **kw))
    print (u'')
    print (u';ANSWER')
    for rrset in r.answer:
        print (rrset.to_text(origin, relativize, **kw))
    print (u'')
    if r.authority!=[]:
        print (u';AUTHORITY')
        for rrset in r.authority:
            print (rrset.to_text(origin, relativize, **kw))
        print (u'')
    """if r.additional != []:
        print (u';ADDITIONAL')
        for rrset in r.additional:
            print (rrset.to_text(origin, relativize, **kw))
        print (u'')"""

def dig(website,servers,type='A'):
    qname = dns.name.from_text(website)
    if type=='A':
        q = dns.message.make_query(qname, dns.rdatatype.A)
    if type=='NS':
        q = dns.message.make_query(qname, dns.rdatatype.NS)
    if type=='MX':
        q = dns.message.make_query(qname, dns.rdatatype.MX)

    for server in servers:
        try:
            response = dns.query.udp(q, server,timeout=4.0,ignore_unexpected=True)
            #print response
            """resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [server]
            resolver.timeout = 4
            response = resolver.query('amazon.com',dns.rdatatype.A) #Using DNS Resolver Class
            print "Servers:",servers
            print response.response"""
            #break
            if response.answer!=[]:
                for entry in response.answer:
                    # print entry
                    # print entry.rdtype
                    # print entry.items
                    if entry.rdtype==dns.rdatatype.from_text(type):
                        return response
                    elif entry.rdtype==dns.rdatatype.from_text('CNAME') and type=='A': #Query the IP address for all the cnames.
                        output = dig(str(entry.items[0].target),rootservers,type)
                    elif entry.rdtype ==dns.rdatatype.from_text('CNAME') and type != 'A':
                        return response
                if output!=None: #If output not node, then CNAME entry found, so we need to add it to final result.
                    for entry in output.answer: #looping through CNAME output and adding it to acutal response output.
                        # print entry
                        # print entry.rdtype
                        # print entry.items
                        response.answer.append(entry)
                    return response
            elif response.additional!=[]:
                for entry in response.additional:
                    #print entry
                    #print entry.rdtype
                    #print entry.items
                    if entry.rdtype==1: #i.e if it is A record then call dig again.
                        output = dig(website,[entry.items[0].address],type)
                        #print output
                        if output!=None:
                            return output

            elif response.authority!=[]:
                for entry in response.authority:
                        for nameserver in entry.items:
                            if nameserver.rdtype==2: #i.e if it is NS record then fetch its IP address and then call dig on it.
                                output = dig(str(nameserver.target),rootservers)
                                #output = dig(website, [str(nameserver.target)])
                                server_ips=[]
                                if output!=None:

                                    for entry in output.answer:
                                        if entry.rdtype==1: #if its A record then add to list of ips found.
                                            for item in entry.items:
                                                server_ips.append(item.address)

                                if server_ips!=[]:
                                    output=dig(website,server_ips,type)
                                    if output!=None:
                                        return output
            #"""
        except:
            #print "Exception Occured"
            continue
    else:
        return None

def main():
    if len(sys.argv)>3:
        print "Provided more than 2 arguments"
    elif len(sys.argv)<2:
        print "Provided less than 1 argument"
    website = sys.argv[1]
    if len(sys.argv)>2:
        type = sys.argv[2]
    else:
        type='A'
    start_time = time.time()
    output = dig(website,rootservers,type)
    end_time = time.time()
    #i=random.randint(30,60)
    if output!=None:
        print_output(output)
        print "Query Time: {}ms".format((end_time - start_time) * 1000)
        print "WHEN: {}".format(time.asctime(time.localtime(end_time)))
        print "MSG SIZE rcvd:",len(output.to_text())

if __name__=='__main__':
    main()

def check_performance():
    for website in alexa_top25_websites:
        average_time = {}
        totaltime = 0.0
        count=0.0
        while (count<10):
            start_time = time.time()
            output = dig(website,rootservers)
            end_time = time.time()
            if output!=None:
                count+=1.0
                totaltime+=(end_time-start_time)
        if count!=0:
            average_time[website]=(totaltime/count)
        else:
            average_time[website]=0
        print website,',',average_time[website]

#check_performance()
