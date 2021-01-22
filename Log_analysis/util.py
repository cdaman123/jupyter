import pandas as pd
from bs4 import BeautifulSoup as bs
import requests
import json
import pycountry 
import re
import urllib
from tqdm.notebook import tqdm

def html_to_df(url, clean_empty = False , attrs = {}, helper = None):
    '''
    Input:
        url : url from which the tabel need to be scrapping.
        clean_empty : if remove completly empty column.
        attrs : html attr. dict tag while more then on table e.g. {'class' : 'class_name'}.
        helper : helper function for cleaning df.
    Output:
        df : dataframe
    '''
    html_content = requests.get(url).text
    soup = bs(html_content, "lxml")
    table = str(soup.find("table", attrs=attrs))
    df = pd.read_html(str(table))[0]
    
    if clean_empty :
        df = df.loc[:, ~df.isnull().all(axis = 0)]
        
    if helper:
        df = helper(df)   
    return df

def ip_loc(x):
    '''
    input:
        x : ip address
    output:
        dictionary which contain country,latitude and longitude.
    '''
    url = "https://geolocation-db.com/jsonp/"+x
    with urllib.request.urlopen(url) as url:
        data = json.loads(url.read().decode().split("(")[1].strip(")"))
    return {"country_code":data["country_code"], 'latitude':data['latitude'],'longitude':data['longitude']}

def loc_dict_maker(series):
    '''
    input:
        series: series of unique ip address.
    output:
        res: dict contain country code, lat, long.
    '''
    res = {}
    for ip in tqdm(series):
        res[ip] = ip_loc(ip)
    return res
    

def alpha3code(column):
    '''
    input:
        column : pandas series.
    output:
        return 3-leter country code
    '''
    CODE=[]
    for country in column:
        try:
            code=pycountry.countries.get(alpha_2=country).alpha_3
            CODE.append(code)
        except:
            CODE.append('None')
    return CODE

def log_parser_re(str_):
    '''
    input:
        str_ : log string.
    output:
        return a dictionary which contain all element of log string.
    '''
    finder = [r'(?P<ip>\A\w+[.]\w+[.]+\w+[.]+\w+)',
              r'(?P<RFC931>\S+)',
              r'(?P<user>\S+)',
              r'\[(?P<date>\d{2}/[a-zA-Z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) (?P<gmt>[+-]\d{4})]',
              r'"(?P<action>.*) HTTP/\d*\.*\d*"',
              r'(?P<status>[0-9]*)',
              r'(?P<size>\S*)',
              r'"(?P<referrer>.*)" "(?P<browser>.*)"']
    m = re.search(' '.join(finder),str_)
    return m.groupdict()

def log_parser(str_):
    '''
    input:
        str_ : log string.
    output:
        return a dictionary which contain all element of log string.
    '''
    find = {}
    find['ip'] = str_.split()[0]
    find['RFC931'] = str_.split()[1]
    find['user'] = str_.split()[2]
    find['date'] = str_.split('[')[1].split()[0]
    find['gmt'] = str_.split('[')[1].split()[1].strip(']')
    try:
        if 'HTTP' in str_.split('"')[1].split()[-1]:
            find['action'] =  str_.split('"')[1].replace(str_.split('"')[1].split()[2],'').strip()
        else:
            find['action'] =  str_.split('"')[1].strip()
    except:
        find['action'] = '-'
    try:
        find['status'] = str_.split('"')[2].strip().split()[0]
    except:
        find['status'] = '-'
    try:
        find['size'] = str_.split('"')[2].strip().split()[1]
    except:
        find['size'] = '-'
    try:
        find['referrer'] = str_.strip().split('"')[3]
    except:
        find['referrer'] ='-'
    try:
        find['browser'] = str_.strip().split('"')[5]
    except:
        find['browser'] = '-'
        
    return find

def log_df(df,col_name ,columns = [] ):
    '''
    input: 
        df : dataframe
        col_name : column name of dataframe on which we need to apply function.
        columns : column name for new dataframe.
    output:
        return new dataframe.
    '''
    df = pd.DataFrame(list(df[col_name].apply(log_parser).values) )
    if len(df.columns) == len(columns):
        df.columns = columns
    return df
    
    
def XSS_finder(str_):
    flag = 0
    l1 = ['<','>','\\','`']
    l2 = ['/',')','(']
    for char in l1:
        aasci_encoding = '%'+hex(ord(char)).replace('0x','')
        if (char in str_) or (aasci_encoding in str_):
            flag = 1
            break
    if flag != 1:
        try:
            req_str = ''.join(str_.split('?')[1:])
            for char in l2:
                aasci_encoding = '%'+hex(ord(char)).replace('0x','')
                if (char in req_str) or (aasci_encoding in req_str):
                    flag = 1
                    break
        except:
            pass
    return bool(flag)
    
    
    