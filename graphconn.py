###########################################################
# Author: Ray Zupancic (with misc contributions from stackoverflow)
# Program: map_threats.py
#
#
#
###########################################################
import networkx as nx
import re
import pandas as pd
import numpy as np







##########################################################
# name: load_conns(df)
# desc: load up the conversations from log file
# columns of log file follow:
# sequence, code, sender, sender_port, receiver, receiver_port, tranport, protocol, time
# input:
# output: nx.Graph # simple graph
#
##########################################################
def load_conns(df):
    # create a collection of elements
    # key node# : IP,desc,serial or uuid, flagged
    cols = ['seq','code','sender','s-port','receiver','r_port','transport','protocol','time','A','B','C',\
           'D','E','F','G','H','I','J','K']
    df = pd.read_csv('conn3.log',header=None)
    df.columns=cols
    return df



##########################################################
# name: get_unique_nodes(df)
# desc: parse dataframe for unique nodes
# input:
# output: list lst # list of unique nodes
#
##########################################################
def get_unique_nodes(df):
    # parse conversation data
    lst = df.sender.unique().tolist()
    lst = lst + df.receiver.unique().tolist()
    return lst


##########################################################
# name: set_nodes_graph(lst,g)
# desc: build a graph with nodes from the dataframe
# input: List lst #list of nodes
# output: nx.Graph # simple graph
#
##########################################################
def set_nodes_graph(lst,g):
    # add the list one by one into a graph
    g.add_nodes_from(lst)



##########################################################
# name: set_edges_graph(g,df)
# desc: build a graph with nodes from the dataframe
# input:
# output: nx.Graph # simple graph
#
##########################################################
def set_edges_graph(df,g):
    # parse conversation data
    for index, row in df.iterrows():
        g.add_edge(row['sender'],row['receiver'],weight=row['weight'],protocol=row['protocol'])



##########################################################
# name: get_weights_column(df)
# desc: count the conversatons and return a DataFrame with a weights column
# input: pd.DataFrame df
# ouput: pd.DataFrame wf
#
##########################################################
def get_weights(df):
    wf = df.groupby(['sender','receiver','r_port','transport','protocol']).size().reset_index().rename(columns=\
                    {0:'weight'})
    return wf


##########################################################
# name: resolve_protocols(pf)
# desc: use a table of port resolutions to resolve a protocol
# input: pd.DataFrame pf
# ouput: pd.DataFrame pf
#
##########################################################
def resolve_protocols(pf):
    pdict = {20:'ftp',21:'ftp',22:'ssh',23:'telnet',80:'http',443:'https',137:'ms-nb',139:'ms-nb',\
            445:'ms-nb',53:'dns',25:'smtp'\
            ,389:'ldap',49160:'pa-ha',636:'sldap',2:'cn',143:'imap',161:'snmp',161:'snmp'}
    for key,value in pdict.items():
        #print(key,':',value)
        pf['protocol'].loc[pf['r_port'] == key] = value
    return pf
             

##########################################################
# name: read_file(filename)
# desc: read file into list
# input: string filename
# ouput: list lines
#
##########################################################
def read_file(filename):
    lines = []
    with open(filename) as file:
        for line in file: 
            line = line.strip() 
            lines.append(line) 
    return lines

##########################################################
# name: color_threats(g, u_lst, t_lst, e_lst)
# desc: add a color attribute to designate threat nodes
# input: nx.Graph g, list lst , list lst
# output: na
# notes: unique list, threats list and external IPs list are used to color 
# connected nodes
#
##########################################################
def color_threats(g, u_lst , t_lst, e_lst):
     # e_lst is the list of external IPs
     # if an address is external, color it blue
     ext = re.compile(r'^192.168.*|^10.')
     for j in e_lst:
         if not ext.match(j):
             g.node[j]['viz'] = {'color': {'r': 0, 'g': 0, 'b': 255, 'a': 0}}
         else:
             g.node[j]['viz'] = {'color': {'r': 34, 'g': 139, 'b': 34, 'a': 0}}

     # color the malware nodes
     risk_nodes =  list(set(u_lst).intersection(t_lst))
     #print (common)
     for i in risk_nodes:
         #g.add_node(i, color="red")
         g.node[i]['viz'] = {'color': {'r': 255, 'g': 0, 'b': 0, 'a': 0}}



##########################################################
# name: main routine
##########################################################
def main():

    df = pd.DataFrame()
    # put conversation in the form of a dataframe
    df = load_conns(df)

    # get unique addresses to use as nodes
    unique_list = get_unique_nodes(df)
    #print(unique_list)

    # get weights (number of conversations between nodes)
    wf = get_weights(df)
    #print(wf)

    # read file into list
    filename = 'threats.log'
    threats_list = read_file(filename)
    #print(threats_list)

    # resolve protocols
    wf = resolve_protocols(wf)
    #print( wf)

    # initialize a graph and then build nodes and edges
    conn_graph = nx.MultiGraph()
    set_nodes_graph(unique_list, conn_graph)
    set_edges_graph(wf,conn_graph)

    # add color to threat nodes
    color_threats(conn_graph, unique_list, threats_list, unique_list)

    print(nx.info(conn_graph))
    nx.write_gexf(conn_graph,"conn_graph.gexf")

main()
