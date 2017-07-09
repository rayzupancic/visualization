import networkx as nx
import pandas as pd
import numpy as np

def load_hosts():
    # create a collection of elements
    # key node# : IP,desc,serial or uuid, flagged
    dict_ips = {1:['192.168.10.1','VLANA-HSRP','na',0],
            2:['192.168.10.4','VLAN1-SwitchA','na',0],
    ind = np.arange(1,len(dict_ips)+1)
    return pd.DataFrame(list(dict_ips.values()), index=ind, columns=['IP','desc','serial','flagged'])


def load_threats():
    # bad IPs
    cols = columns=['IP','desc','serial','flagged']
    dict_bad_ips = { 1:['10.3.2.2','Bad_Actor_URL','http://www.badactor.ishe',1],
                     2:['10.3.2.4','Bad_Actor_URL','http://www.badactor.ishe',1] }
    ind = np.arange(1,len(dict_bad_ips)+1)

    return pd.DataFrame(list(dict_bad_ips.values()), index=ind, columns=cols)
             
def load_conversations():
    # parse conversation data
    # key: to,from, protocol,quan
    cols = columns=['fromIP','toIP','protocol','quan']
    dict_conns = {1:['192.168.10.36','10.3.2.2','http',17],
            2:['192.168.10.5','10.3.2.2','http',18],
            13:['192.168.10.35','192.168.10.45','smb',20]}
    ind = np.arange(1,len(dict_conns)+1)
    return pd.DataFrame(list(dict_conns.values()), index=ind, columns=cols)


##########################################################
# name: count_common(df)
# desc:
# input:
# ouput:
#
##########################################################
def count_common(df):
    


def main():


    df = pd.read_csv('graph_conn2.log',header=None)
    cols = ['seq','code','sender','s-port','receiever','r-port','transport','protocol','time','A','B','C','D','E','F','G','H','I','J','K']
    df.columns=cols
    print(df)
    G  = nx.Graph()
    # load bad IPs dataframe
    #bad_df = load_threats()
    # load hosts dataframe
    #hosts_df = load_hosts()
    #print (hosts_df)


main()
