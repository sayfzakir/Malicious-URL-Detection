import re
import requests
import http.client
import urllib
import whois
import datetime

Suspicious_Words=['secure','account','update','banking','login','click','confirm','password','verify','signin','ebayisapi','lucky','bonus']

Suspicious_TLD=['zip','cricket','link','work','party','gq','kim','country','science','tk']

def Total_Dots(link):
    dot='.'
    count=0
    for i in link:
        if i==dot:
            count+=1
    return count

def Total_Delims(str):
    delim=['-','_','?','=','&']
    count=0
    for i in str:
        for j in delim:
            if i==j:
                count+=1
    return count


def no_of_hyphens_in_domain(link):
    hyph='-'
    count=0
    for i in link:
        if i==hyph:
            count+=1
    return count

def ip_presence(lis):
    for i in lis:
        if i.isdigit()==False:
            return 0
    else:
        return 1

def Construct_Vector(mystr):
    vec=[]
    removed_protocol=re.sub(r'^http(s*)://','',mystr)

    vec.append(len(removed_protocol))
    vec.append(Total_Dots(removed_protocol))


    for i in Suspicious_Words:
        if re.search(i,removed_protocol,re.IGNORECASE):
            vec.append(1)
            break
    else:
        vec.append(0)


    patt=r'^[^/]*'
    patt_path=r'/[^/]*'
    dom=re.match(patt,removed_protocol).group(0)
    info=re.findall(patt_path,removed_protocol)
    ###print('Domain Name: ',dom)
    doma_hyph_count=no_of_hyphens_in_domain(dom)
    vec.append(int(doma_hyph_count))
    domain_Tokens=(dom).split('.')
    domain_Tokens=[x for x in domain_Tokens if x!='']
    ##print('Domain Length: ',len(dom))
    path_tokens=[re.sub('/','',x) for x in info]
    if path_tokens!=[]:
        file_n_args=path_tokens[-1]
    else:
        file_n_args=''
    path_tokens=path_tokens[:-1]
    info=[x for x in info if x!='']
    slashes=len(info)
    #print('Slashes:',slashes)
    dir_len=0
    for i in (path_tokens):
        dir_len+=len(i)
    dir_len+=slashes
    vec.append(int(dir_len))
    #print('Directory Length: ',dir_len)
    num_subdir=len(path_tokens)
    #print('Number of Subdirectories :',num_subdir)
    vec.append(num_subdir)
    #print('Path Tokens : ',path_tokens)
    TLD=domain_Tokens[-1]	
    #print('Top Level Domain :',TLD)
    vec.append(len(dom)) 
    vec.append(len(domain_Tokens))
    vec.append(len(path_tokens)) 
    #asn_num=msh.check(dom)
    is_ip=ip_presence(domain_Tokens)
    vec.append(is_ip) 
    ##print('ASN number :',asn_num)
    domain_tok_lengts=[]
    for i in domain_Tokens:
        domain_tok_lengts.append(len(i))
    largest_dom_token_len=max(domain_tok_lengts)
    vec.append(largest_dom_token_len) 

    avg_dom_Tok_len=float(sum(domain_tok_lengts))/len(domain_tok_lengts)

    vec.append(avg_dom_Tok_len)

    path_tok_lengts=[]
    path_tok_dots=0
    path_tok_delims=0
    avg_path_Tok_len=0
    largest_path_token_len=0
    if len(path_tokens):
        for i in path_tokens:
            path_tok_lengts.append(len(i))
            path_tok_dots=Total_Dots(i)
            path_tok_delims=Total_Delims(i)
        avg_path_Tok_len=float(sum(path_tok_lengts))/len(path_tok_lengts)
        largest_path_token_len=max(path_tok_lengts)
        vec.append(largest_path_token_len) 
        vec.append(avg_path_Tok_len)
    else:
        vec.append(largest_path_token_len)
        vec.append(avg_path_Tok_len)
    #print('Largest Path Token Length:',largest_path_token_len)
    #print('Path Token Total Dots:',path_tok_dots)
    #print('Path Token Delims:',path_tok_delims)
    if is_ip:
        vec.append(0)
    else:
        for i in Suspicious_TLD:
            if re.search(i,TLD,re.IGNORECASE):
                vec.append(1)
                break
        else:
            vec.append(0)
    if file_n_args!='':
        tmp=file_n_args.split('?')
        file=tmp[0]
        if len(tmp)>1:
            args=tmp[1]
        else:
            args=''
        #print('File:',file)
        #print('Arguments:',args)
        vec.append(len(file))
        vec.append(Total_Dots(file))
        vec.append(Total_Delims(file))
        #print('Total dots in file: ',Total_Dots(file))
        #print('Total Delims in file: ',Total_Delims(file))

        if args=='':
            vec.append(0)
            vec.append(0)
            vec.append(0)
            vec.append(0)
            #print('argument length:',0)
            #print('number of arguments:',0)
            #print('length of Largest variable value:',0)
            #print('Maximun no of delims:',0)

        else:
            vec.append(len(args)+1)
            #print('argument length:',len(args)+1)
            arb=args.split('&')
            vec.append(len(arb))
            #print('Number of arguments',len(arb))
            len_var=[]
            max_delim=[]
            for i in arb:
                tmp=i.split('=')
                if len(tmp)>1:
                    len_var.append(len(tmp[1]))
                    max_delim.append(Total_Delims(tmp[0]))
                    max_delim.append(Total_Delims(tmp[1]))
                else:
                    len_var.append(0)
                    max_delim.append(0)
            vec.append(max(len_var))
            #print('length of Largest variable value:',max(len_var))
            max_delim=max(max_delim)
            vec.append(max_delim)
            #print('Maximum no of delims:',max_delim)
    else:
            vec.append(0)
            vec.append(0)
            vec.append(0)
            vec.append(0)
            vec.append(0)
            vec.append(0)
            vec.append(0)
        #print('argument length:',0)
        #print('number of arguments:',0)

    avg_month_time=365.2425/12.0

    while(True):
        if(not dom[-1].isalnum()):
            dom=dom[:-1]
        else:
            break

    try:
        who_info=whois.whois(dom)
    except Exception:
        vec.append(-1)
        vec.append(-1)
        vec.append(-1)
        vec.append(-1)
        return vec

    if(who_info.creation_date == None and who_info.expiration_date == None and who_info.updated_date == None and who_info.zipcode == None):
        vec.append(-1)
        vec.append(-1)
        vec.append(-1)
        vec.append(-1)
        return vec

    if(who_info.creation_date==None or type(who_info.creation_date) is str):
        vec.append(-1)
    else:
        if(type(who_info.creation_date) is list): 
            create_date=who_info.creation_date[-1]
        else:
            create_date=who_info.creation_date
        if(type(create_date) is datetime.datetime):
            today_date=datetime.datetime.now()
            create_age_in_mon=((today_date - create_date).days)/avg_month_time
            create_age_in_mon=round(create_age_in_mon)
            vec.append(create_age_in_mon)
        else:
            vec.append(-1)

    if(who_info.expiration_date==None or type(who_info.expiration_date) is str):
        vec.append(-1)
    else:
        if(type(who_info.expiration_date) is list):
            expiry_date=who_info.expiration_date[-1]
        else:
            expiry_date=who_info.expiration_date
        if(type(expiry_date) is datetime.datetime):
            today_date=datetime.datetime.now()
            expiry_age_in_mon=((expiry_date - today_date).days)/avg_month_time
            expiry_age_in_mon=round(expiry_age_in_mon)
            vec.append(expiry_age_in_mon)
        else:
            vec.append(-1)

    if(who_info.updated_date==None or type(who_info.updated_date) is str):
        vec.append(-1)
    else:
        if(type(who_info.updated_date) is list):
            update_date=who_info.updated_date[-1]
        else:
            update_date=who_info.updated_date
        if(type(update_date) is datetime.datetime):
            today_date=datetime.datetime.now()
            update_age_in_days=((today_date - update_date).days)
            vec.append(update_age_in_days)
        else:
            vec.append(-1)


    zipcode=who_info.zipcode
    if(zipcode == None or (type(zipcode) is not str)):
        zipcode=-1
    else:
        if '-' in zipcode:
            zipcode=re.sub('-*','',zipcode)
        zipcode=re.sub(r'[A-Za-z\s]*','',zipcode)

    if(type(zipcode) is str and zipcode.isdigit()):
        vec.append(int(zipcode))
    else:
        zipcode=-1
        vec.append(zipcode)
    return vec