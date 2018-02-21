import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import dns.resolver
import dns.rdata
import sys
import time

rootservers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
               '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

rootkey_digests = ['49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5', 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D']

rootkey_digest_type = 2

#rootservers information obtained from "https://www.iana.org/domains/root/servers"

def dnssec_query(website,servers,is_root=True,ds_set=None,ns='.',type='A'):
    #try:
    for server in servers:
        #print server
        #print "###########"

        try:
            qname = dns.name.from_text(website)
            website_query = dns.message.make_query(qname, dns.rdatatype.A, want_dnssec=True)
            website_response = dns.query.tcp(website_query, server, timeout=2.0)

            #ns='org'
            nsname = dns.name.from_text(ns)
            ns_query = dns.message.make_query(nsname, dns.rdatatype.DNSKEY, want_dnssec=True)
            ns_response = dns.query.tcp(ns_query, server, timeout=2.0)
        except:
            #print "Timeout Occured"
            continue

        #print website_response
        #print "###########"
        #print ns_response
        #print "###########"


        ns_rrsig_set = None
        ns_ds_set = None
        ns_rrset=None
        zsk_set = None
        zsk = None
        ksk_set = None
        ksk = []

        if(ns_response.answer!=[]):
            for entry in ns_response.answer:
                if entry.rdtype==48:    #this means that it is DNSKEY, so extract KSK and ZSK from it
                    ns_rrset = entry
                    for item in entry.items:
                        if item.flags==256:
                            zsk=item
                            zsk_set=entry
                        if item.flags==257:
                            ksk_set=entry
                            ksk.append(item)

                if entry.rdtype == 46:  # this means that it is RRSIG
                    ns_rrsig_set = entry
        elif(ns_response.authority!=[]):
            for entry in ns_response.authority:
                if entry.rdtype == 46:
                    ns_rrsig_set = entry
                if entry.rdtype == 43:
                    ns_ds_set = entry

        else:
            print "DNSSEC not supported"
            exit(0)
            return None

        if ns_rrsig_set==None:
            print "DNSSEC not supported"
            exit(0)

        if zsk==None or ksk==None or ns_rrset==None:
            print "DNSSec verification failed"
            exit(0)
            return None

        #website_ds=None
        website_rrsig_set=None
        website_rrset=None
        website_ds_set = None
        nsec_records = []

        if website_response.answer != []:
            for entry in website_response.answer:
                if entry.rdtype == 43:  # this means that it is DS Record, which will be passed to child query for verification
                    #website_ds = entry.items[0]
                    website_ds_set = entry
                if entry.rdtype == 46: #this means it is RRSIG
                    website_rrsig_set = entry
                if entry.rdtype == 1:  # this means that it is NS RRset, which will be used further resolution
                    website_rrset = entry

            if website_rrsig_set == None:
                print "DNSSEC not supported"
                exit(0)
                break
            if website_rrset != None:
                #return None
                # validation of RRset using zsk
                try:
                    dns.dnssec.validate(website_rrset,website_rrsig_set, {nsname: zsk_set})
                except:
                    print "DNSSec verification failed"
                    exit(0)
                    break
                    #return None

        elif (website_response.authority != []):
            for entry in website_response.authority:
                if entry.rdtype == 43:  # this means that it is DS Record, which will be passed to child query for verification
                    #website_ds = entry.items[0]
                    website_ds_set = entry
                if entry.rdtype == 46: #this means it is RRSIG
                    website_rrsig_set = entry
                if entry.rdtype == 2:  # this means that it is NS RRset, which will be used further resolution
                    website_rrset = entry
                if entry.rdtype == 50 or entry.rdtype==47:  # this means that it is NSEC record
                    nsec_name = entry.name.to_text()
                    for entry1 in website_response.authority:
                        if entry1.name.to_text()==nsec_name:
                            nsec_records.append((entry,entry1))
                            break

            if website_rrsig_set == None:
                print "DNSSEC not supported"
                exit(0)
                break

            if website_ds_set != None and website_rrsig_set != None:

                # validation of RRset using zsk
                try:
                    dns.dnssec.validate(website_ds_set,website_rrsig_set, {nsname: zsk_set})
                except:
                    print "DNSSec verification failed"
                    exit(0)
                    break
                    #return None

            if nsec_records != []:
                pass
                """print "DNSSEC not supported"
                exit(0)
                for entry in nsec_records:
                    try:
                        dns.dnssec.validate(entry[0], entry[1], {nsname: zsk_set})
                    except:
                        print "DNSSec verification failed"
                        exit(0)
                        break
                        #return None"""

            """if website_ds_set == None and website_rrsig_set == None and website_rrset==None:
                print "DNSSec verification failed"
                exit(0)
                break
                #return None"""

        else:
            """print "DNSSec verification failed"
            exit(0)
            break"""
            return None

        #validation of DNSKEY RRset using ksk
        try:
            dns.dnssec.validate(ns_rrset,ns_rrsig_set,{nsname:ksk_set})
        except:
            print "DNSSec verification failed"
            exit(0)
            break
            #return None


        #validation of DS record

        if is_root!=True and ds_set!=None:
            for item in ds_set.items:
                success=False
                for key in ksk:
                    if item.digest_type==1:
                        duplicate_ds = dns.dnssec.make_ds(ns, key, "SHA1")
                    if item.digest_type==2:
                        duplicate_ds = dns.dnssec.make_ds(ns, key, "SHA256")
                    if duplicate_ds!=None and duplicate_ds.digest == item.digest:
                        success = True
                        break
                if success==True:
                    break
            if success!=True:
                print "DNSSec verification failed"
                exit(0)
                #return None

        if is_root!=True and ds_set==None:
            print "DNSSec verification failed"
            exit(0)
            break

        if is_root==True:
            success = False
            for key in ksk:
                duplicate_ds = dns.dnssec.make_ds(ns, key, "SHA256")
                if duplicate_ds != None:
                    temp1 = dns.rdata._hexify(duplicate_ds.digest).upper()
                    temp1 = ''.join(temp1.split(' '))
                    for i in rootkey_digests:
                        if i in temp1:
                            success = True
                            break

            if success != True:
                print "DNSSec verification failed"
                exit(0)

        response = website_response

        if response.answer != []:
            for entry in response.answer:
                if entry.rdtype == dns.rdatatype.from_text(type):
                    return response
                elif entry.rdtype == dns.rdatatype.from_text(
                        'CNAME') and type == 'A':  # Query the IP address for all the cnames.
                    output = dnssec_query(str(entry.items[0].target), rootservers,True,None)
                elif entry.rdtype == dns.rdatatype.from_text('CNAME') and type != 'A':
                    return response
            if output != None:  # If output not node, then CNAME entry found, so we need to add it to final result.
                for entry in output.answer:  # looping through CNAME output and adding it to acutal response output.
                    response.answer.append(entry)
                return response
        elif response.additional != []:
            for entry in response.additional:
                if entry.rdtype == 1:  # i.e if it is A record then call dig again.
                    temp=None
                    for entry1 in response.authority:
                        if entry1.rdtype==2:
                            temp=entry1.name.to_text()
                            break
                    output = dnssec_query(website, [entry.items[0].address], False, website_ds_set,temp)
                    if output != None:
                        return output

        elif response.authority != []:
            for entry in response.authority:
                for nameserver in entry.items:
                    if nameserver.rdtype == 2:  # i.e if it is NS record then fetch its IP address and then call dig on it.
                        #output = dnssec_query(str(nameserver.target), rootservers,True,None)
                        resolver = dns.resolver.Resolver(configure=False)
                        resolver.nameservers = ['8.8.8.8']
                        resolver.timeout = 4
                        response = resolver.query(str(nameserver.target), dns.rdatatype.A)
                        output = response.response
                        # output = dig(website, [str(nameserver.target)])
                        server_ips = []
                        if output != None:

                            for entry in output.answer:
                                if entry.rdtype == 1:  # if its A record then add to list of ips found.
                                    for item in entry.items:
                                        server_ips.append((item.address,entry.name.to_text()))

                        if server_ips != []:
                            for (server1,tempns) in server_ips:
                                if website_ds_set!=None:
                                    output = dnssec_query(website, [server1], False,website_ds_set,website_ds_set.name.to_text()) #need to check here.
                                else:
                                    output = dnssec_query(website, [server1], False,website_ds_set,website_ds_set)
                                if output != None:
                                    return output

    return None

#output = dnssec_query('www.cnn.com',rootservers)

#print output

#took this print function from the inbuilt library..
def print_output(r, **kw):
    for entry in r.answer:
        if entry.rdtype==1:
            for item in entry.items:
                print "IPAddress of {} = ".format(entry.name.to_text(omit_final_dot=True)), str(item.address)

def main():
    if len(sys.argv)>2:
        print "Provided more than 1 arguments"
    elif len(sys.argv)<2:
        print "Provided less than 1 argument"
    website = sys.argv[1]
    start_time = time.time()
    output = dnssec_query(website,rootservers)
    end_time = time.time()
    if output!=None:
        print_output(output)

if __name__=='__main__':
    main()


